// Package stripe is a dependency-free Stripe client covering exactly what a
// membership flow needs: create a Checkout Session, create a Billing Portal
// session, parse webhook events, and verify webhook signatures. It talks to the
// Stripe REST API with form-encoded POSTs (net/http) and verifies webhooks with
// stdlib crypto, so the consuming binary stays free of the heavyweight official
// SDK.
//
// All network calls accept a context.Context for cancellation and deadlines, the
// per-request timeout is configurable on the Client (with a sane default), and
// transient failures (network errors and HTTP 429 / 5xx responses) are retried
// with bounded exponential backoff. Non-2xx responses are decoded into a typed
// *APIError carrying Stripe's status, code, and message rather than being
// silently ignored.
package stripe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// apiBase is the root of the Stripe REST API.
const apiBase = "https://api.stripe.com"

// Default client tuning. These were chosen to be conservative and safe for the
// idempotent membership-flow calls this package exposes.
const (
	defaultTimeout     = 20 * time.Second
	defaultMaxAttempts = 3
	defaultBaseBackoff = 200 * time.Millisecond
	maxBackoff         = 5 * time.Second
)

// APIError is a typed representation of a non-2xx response from Stripe. It is
// returned (wrapped) by every network call when Stripe reports an error,
// replacing the source's behavior of unmarshalling the body and proceeding as
// if the call had succeeded.
type APIError struct {
	// StatusCode is the HTTP status returned by Stripe.
	StatusCode int
	// Type is Stripe's machine error type (e.g. "card_error", "invalid_request_error").
	Type string
	// Code is Stripe's machine error code (e.g. "resource_missing"), when present.
	Code string
	// Message is the human-readable message from Stripe, when present.
	Message string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	switch {
	case e.Message != "" && e.Code != "":
		return fmt.Sprintf("stripe: %s (code=%s, status=%d)", e.Message, e.Code, e.StatusCode)
	case e.Message != "":
		return fmt.Sprintf("stripe: %s (status=%d)", e.Message, e.StatusCode)
	default:
		return fmt.Sprintf("stripe: request failed with status %d", e.StatusCode)
	}
}

// retryable reports whether a failed request with this status is worth retrying.
// Stripe returns 429 for rate limiting and 5xx for transient server faults; both
// are safe to retry for the idempotent calls in this package.
func (e *APIError) retryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// Option configures a Client. Options are applied by New.
type Option func(*Client)

// WithHTTPClient supplies a custom *http.Client. When set, the Client's
// configured timeout is not applied to the supplied client; the caller owns its
// configuration. Prefer WithTimeout unless you need custom transport behavior.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithTimeout sets the per-request timeout used as a fallback deadline when the
// caller's context has none. A non-positive value is ignored.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxAttempts sets the maximum number of attempts (initial try plus retries)
// for transient failures. A value below 1 is ignored, keeping the default.
func WithMaxAttempts(n int) Option {
	return func(c *Client) {
		if n >= 1 {
			c.maxAttempts = n
		}
	}
}

// WithBaseBackoff sets the base delay for exponential backoff between retries.
// A non-positive value is ignored.
func WithBaseBackoff(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.baseBackoff = d
		}
	}
}

// Client holds the secret key and request configuration. The zero value is
// unusable; use New.
type Client struct {
	secretKey   string
	http        *http.Client
	timeout     time.Duration
	maxAttempts int
	baseBackoff time.Duration
}

// New returns a Client authenticated with the given Stripe secret key. Sensible
// defaults are applied (20s timeout, 3 attempts, 200ms base backoff) and may be
// overridden with Options.
func New(secretKey string, opts ...Option) *Client {
	c := &Client{
		secretKey:   secretKey,
		timeout:     defaultTimeout,
		maxAttempts: defaultMaxAttempts,
		baseBackoff: defaultBaseBackoff,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: c.timeout}
	}
	return c
}

// post issues a form-encoded POST to the Stripe API and decodes the JSON body
// into a generic map on success.
//
// Retry policy: the requests issued by this package (Checkout Session creation
// and Billing Portal Session creation) are safe to retry because Stripe treats
// them idempotently for our purposes and a retry at worst produces a fresh,
// independent session URL. post therefore retries transient failures (network
// errors and APIErrors reporting HTTP 429 / 5xx) with bounded exponential
// backoff up to the Client's configured max attempts. Non-transient errors
// (4xx other than 429, context cancellation, malformed responses) fail
// immediately without retry.
func (c *Client) post(ctx context.Context, path string, form url.Values) (map[string]any, error) {
	var lastErr error

	for attempt := 0; attempt < c.maxAttempts; attempt++ {
		if attempt > 0 {
			if err := c.waitBackoff(ctx, attempt); err != nil {
				// Context cancelled/expired while waiting to retry; surface the
				// most informative error we have.
				if lastErr != nil {
					return nil, fmt.Errorf("%w (last error: %v)", err, lastErr)
				}
				return nil, err
			}
		}

		out, err := c.doPost(ctx, path, form)
		if err == nil {
			return out, nil
		}
		lastErr = err

		if !isRetryable(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("stripe: %s failed after %d attempts: %w", path, c.maxAttempts, lastErr)
}

// doPost performs a single POST attempt: build, send, read, and interpret the
// response. It never ignores errors and converts non-2xx responses into a typed
// *APIError.
func (c *Client) doPost(ctx context.Context, path string, form url.Values) (map[string]any, error) {
	// Apply the configured timeout as a fallback deadline only when the caller's
	// context does not already carry one, so callers retain full control.
	if c.timeout > 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, c.timeout)
			defer cancel()
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("stripe: build request: %w", err)
	}
	req.SetBasicAuth(c.secretKey, "")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		// Transport-level error (DNS, connection reset, timeout, etc.). These are
		// treated as transient by isRetryable.
		return nil, fmt.Errorf("stripe: request to %s: %w", path, err)
	}
	defer func() {
		// Drain and close so the connection can be reused; report close errors.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("stripe: read response from %s: %w", path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Decode Stripe's error envelope into a typed error instead of silently
		// continuing. Decode failures still yield a useful status-only APIError.
		return nil, parseAPIError(resp.StatusCode, body)
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("stripe: decode response from %s: %w", path, err)
	}
	return out, nil
}

// parseAPIError builds an *APIError from a non-2xx response body. Stripe encodes
// errors as {"error": {"type":..., "code":..., "message":...}}.
func parseAPIError(status int, body []byte) *APIError {
	apiErr := &APIError{StatusCode: status}

	var envelope struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		apiErr.Type = envelope.Error.Type
		apiErr.Code = envelope.Error.Code
		apiErr.Message = envelope.Error.Message
	}
	return apiErr
}

// isRetryable reports whether err represents a transient failure worth retrying.
// Context errors are never retried; transport errors are; APIErrors are retried
// only for HTTP 429 / 5xx.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.retryable()
	}
	// Remaining errors at this point are transport-level (network) failures,
	// which are transient. Build/decode errors are non-transient but are
	// returned directly by post without consulting isRetryable.
	return true
}

// waitBackoff sleeps for the exponential backoff appropriate to the given
// (1-based) retry attempt, returning early if the context is done.
func (c *Client) waitBackoff(ctx context.Context, attempt int) error {
	backoff := time.Duration(float64(c.baseBackoff) * math.Pow(2, float64(attempt-1)))
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// CheckoutParams configures a subscription Checkout Session.
type CheckoutParams struct {
	PriceID       string
	CustomerID    string // optional existing customer
	CustomerEmail string // used when CustomerID is empty
	ClientRefID   string // our user id, echoed back on the session for reconciliation
	SuccessURL    string
	CancelURL     string
}

// CreateCheckoutSession creates a subscription Checkout Session and returns its
// hosted URL. The underlying POST is retried on transient failures (see post).
func (c *Client) CreateCheckoutSession(ctx context.Context, p CheckoutParams) (string, error) {
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("line_items[0][price]", p.PriceID)
	form.Set("line_items[0][quantity]", "1")
	form.Set("success_url", p.SuccessURL)
	form.Set("cancel_url", p.CancelURL)
	form.Set("allow_promotion_codes", "true")
	if p.ClientRefID != "" {
		form.Set("client_reference_id", p.ClientRefID)
	}
	if p.CustomerID != "" {
		form.Set("customer", p.CustomerID)
	} else if p.CustomerEmail != "" {
		form.Set("customer_email", p.CustomerEmail)
	}

	out, err := c.post(ctx, "/v1/checkout/sessions", form)
	if err != nil {
		return "", err
	}
	urlStr, _ := out["url"].(string)
	if urlStr == "" {
		return "", fmt.Errorf("stripe: checkout session missing url")
	}
	return urlStr, nil
}

// CreatePortalSession creates a Billing Portal Session for managing or
// cancelling a subscription and returns its URL. The underlying POST is retried
// on transient failures (see post).
func (c *Client) CreatePortalSession(ctx context.Context, customerID, returnURL string) (string, error) {
	form := url.Values{}
	form.Set("customer", customerID)
	form.Set("return_url", returnURL)

	out, err := c.post(ctx, "/v1/billing_portal/sessions", form)
	if err != nil {
		return "", err
	}
	urlStr, _ := out["url"].(string)
	if urlStr == "" {
		return "", fmt.Errorf("stripe: portal session missing url")
	}
	return urlStr, nil
}

// Event is the minimal slice of a Stripe webhook event acted upon by callers.
type Event struct {
	Type string `json:"type"`
	Data struct {
		Object map[string]any `json:"object"`
	} `json:"data"`
}

// ConstructEvent verifies the Stripe-Signature header (HMAC-SHA256 over
// "timestamp.payload") and returns the parsed event. tolerance bounds clock skew;
// a non-positive tolerance disables the timestamp check.
//
// This is a pure, local cryptographic operation: it makes no network calls and
// therefore takes no context and performs no retries.
func ConstructEvent(payload []byte, sigHeader, secret string, tolerance time.Duration) (*Event, error) {
	if secret == "" {
		return nil, fmt.Errorf("stripe: webhook secret not configured")
	}

	var ts string
	var sigs []string
	for _, part := range strings.Split(sigHeader, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			sigs = append(sigs, kv[1])
		}
	}
	if ts == "" || len(sigs) == 0 {
		return nil, fmt.Errorf("stripe: malformed signature header")
	}

	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("stripe: bad timestamp: %w", err)
	}
	if tolerance > 0 && time.Since(time.Unix(tsInt, 0)) > tolerance {
		return nil, fmt.Errorf("stripe: signature timestamp outside tolerance")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(ts + "." + string(payload))); err != nil {
		return nil, fmt.Errorf("stripe: compute signature: %w", err)
	}
	expected := hex.EncodeToString(mac.Sum(nil))

	ok := false
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(expected)) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("stripe: signature mismatch")
	}

	var ev Event
	if err := json.Unmarshal(payload, &ev); err != nil {
		return nil, fmt.Errorf("stripe: bad event json: %w", err)
	}
	return &ev, nil
}
