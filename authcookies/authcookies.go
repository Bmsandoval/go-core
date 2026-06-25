// Package authcookies provides session and CSRF cookie management for
// browser-facing Go services that authenticate against an upstream identity
// provider (e.g. Cognito) and hand a short-lived session to a single-page app.
//
// It writes four session cookies (a JWT, a user identifier, a session
// "deadline", and a session "timer"), an optional CSRF cookie, and a
// server-set X-User-Context header carrying base64-encoded claims.
//
// Unlike the starter implementations this package was distilled from, it makes
// no assumptions about deployment environment. There are no hardcoded checks
// such as cfg.Env == "production": the caller decides cookie security via
// Options.Secure and Options.SameSite. This keeps the package free of any
// configuration dependency and trivially testable.
//
// Cookie security guidance for callers:
//   - In production over HTTPS, set Secure: true. If the SPA and API are on
//     different sites, set SameSite: http.SameSiteNoneMode (which requires
//     Secure: true per the browser spec). For same-site deployments prefer
//     http.SameSiteLaxMode.
//   - In local development over plain HTTP, set Secure: false and
//     SameSite: http.SameSiteLaxMode.
package authcookies

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// Default cookie names. These match the names used by the source starters and
// the SPA code that reads them via document.cookie, so they are the defaults
// applied by Default.
const (
	DefaultJWTName      = "JWT"
	DefaultUserIDName   = "UserID"
	DefaultDeadlineName = "SessionDeadline"
	DefaultTimerName    = "SessionTimer"
	DefaultCSRFName     = "CSRF-Token"

	// DefaultPath is the cookie path applied when Options.Path is empty.
	DefaultPath = "/"

	// csrfHeaderName is the request header the SPA echoes the CSRF cookie
	// value into for double-submit verification.
	csrfHeaderName = "X-CSRF-Token"

	// userContextHeaderName carries base64(JSON(SessionClaims)). It is set by
	// the server and must only be trusted when it originates from the gateway
	// (see EncodeUserContextHeader).
	userContextHeaderName = "X-User-Context"
)

// Options controls how cookies are written. Construct a value with Default and
// override fields as needed; an empty field name falls back to its default.
//
// Secure and SameSite are intentionally not derived from any environment
// detection — the caller is responsible for setting them correctly for the
// deployment.
type Options struct {
	// Secure marks cookies as Secure (HTTPS-only). The caller decides this;
	// there is no implicit "production" check.
	Secure bool

	// SameSite controls the SameSite attribute of every cookie written. Note
	// that http.SameSiteNoneMode requires Secure to be true.
	SameSite http.SameSite

	// Domain optionally scopes cookies to a domain. Empty leaves the cookie
	// host-only (recommended unless cross-subdomain sharing is required).
	Domain string

	// Path is the cookie path. Empty defaults to DefaultPath ("/").
	Path string

	// Cookie names. Each empty value falls back to its Default* constant.
	JWTName      string
	UserIDName   string
	DeadlineName string
	TimerName    string
	CSRFName     string

	// UserIDHttpOnly / DeadlineHttpOnly force the UserID / SessionDeadline cookies
	// to be HttpOnly. They default to false so a SPA can read them (session-presence
	// check / double-submit). Set true on backends where no client reads those
	// cookies and you prefer them locked down.
	UserIDHttpOnly   bool
	DeadlineHttpOnly bool

	// CSRFMaxAge, when > 0, makes the CSRF cookie persistent for that duration
	// instead of a session cookie (the default when 0).
	CSRFMaxAge time.Duration
}

// Default returns Options populated with the default cookie names and a safe,
// development-friendly baseline (Secure: false, SameSite: Lax). Callers should
// override Secure/SameSite/Domain for production.
func Default() Options {
	return Options{
		Secure:       false,
		SameSite:     http.SameSiteLaxMode,
		Path:         DefaultPath,
		JWTName:      DefaultJWTName,
		UserIDName:   DefaultUserIDName,
		DeadlineName: DefaultDeadlineName,
		TimerName:    DefaultTimerName,
		CSRFName:     DefaultCSRFName,
	}
}

// withDefaults returns a copy of o with any empty field replaced by its
// default, so callers can pass a partially-populated Options.
func (o Options) withDefaults() Options {
	if o.Path == "" {
		o.Path = DefaultPath
	}
	if o.JWTName == "" {
		o.JWTName = DefaultJWTName
	}
	if o.UserIDName == "" {
		o.UserIDName = DefaultUserIDName
	}
	if o.DeadlineName == "" {
		o.DeadlineName = DefaultDeadlineName
	}
	if o.TimerName == "" {
		o.TimerName = DefaultTimerName
	}
	if o.CSRFName == "" {
		o.CSRFName = DefaultCSRFName
	}
	return o
}

// SessionParams carries the per-request data needed to write a session.
type SessionParams struct {
	// JWT is the identity/access token stored in the HttpOnly JWT cookie.
	JWT string

	// UserID is the subject identifier (e.g. the Cognito "sub"). It is stored
	// in a non-HttpOnly cookie so the SPA can cheaply check session presence.
	UserID string

	// Deadline is the absolute time at which the session expires. It is
	// published to the SPA as a Unix timestamp in the SessionDeadline cookie.
	Deadline time.Time

	// Timer is the soft-timeout instant published in the SessionTimer cookie —
	// the moment the *idle* window lapses, distinct from the absolute Deadline.
	// In a two-tier session this is now+TokenMaxAge, NOT now+DeadlineMaxAge.
	// Leave it zero to fall back to Deadline (single-tier; backward-compatible).
	Timer time.Time

	// MaxAge is the lifetime applied to every session cookie. Values <= 0 are
	// treated as a session cookie by net/http; pass a positive duration for a
	// persistent session.
	MaxAge time.Duration

	// TokenMaxAge, when > 0, overrides MaxAge for the JWT, UserID, and
	// SessionTimer cookies — the short-lived "token tier" of a two-tier session.
	// DeadlineMaxAge, when > 0, overrides MaxAge for the SessionDeadline cookie —
	// the long-lived "deadline tier" (absolute expiry). Leave both 0 to apply
	// MaxAge to every cookie (single-tier; backward-compatible).
	TokenMaxAge    time.Duration
	DeadlineMaxAge time.Duration
}

// SetSession writes the JWT, UserID, SessionDeadline, and SessionTimer cookies.
//
// The JWT and SessionTimer cookies are HttpOnly (the sensitive token and the
// server-authoritative timer). The UserID and SessionDeadline cookies are
// readable by JavaScript so the SPA can determine session validity client-side
// without exposing the token.
func SetSession(w http.ResponseWriter, p SessionParams, o Options) {
	o = o.withDefaults()
	tokenAge := p.MaxAge
	if p.TokenMaxAge > 0 {
		tokenAge = p.TokenMaxAge
	}
	deadlineAge := p.MaxAge
	if p.DeadlineMaxAge > 0 {
		deadlineAge = p.DeadlineMaxAge
	}
	token := maxAgeSeconds(tokenAge)
	deadline := maxAgeSeconds(deadlineAge)

	// The SessionTimer cookie carries the soft-timeout instant. Fall back to
	// Deadline when Timer is unset so single-tier callers are unaffected.
	timerVal := p.Timer
	if timerVal.IsZero() {
		timerVal = p.Deadline
	}

	http.SetCookie(w, o.cookie(o.JWTName, p.JWT, token, true))
	http.SetCookie(w, o.cookie(o.UserIDName, p.UserID, token, o.UserIDHttpOnly))
	http.SetCookie(w, o.cookie(o.DeadlineName, fmtUnix(p.Deadline), deadline, o.DeadlineHttpOnly))
	http.SetCookie(w, o.cookie(o.TimerName, fmtUnix(timerVal), token, true))
}

// ClearSession expires the four session cookies (JWT, UserID, SessionDeadline,
// SessionTimer) and clears the X-User-Context header so a stale value is never
// propagated downstream.
//
// Each cookie is expired with the SAME HttpOnly posture SetSession wrote it
// with (JWT and SessionTimer always HttpOnly; UserID and SessionDeadline follow
// Options) — though HttpOnly is moot on an already-empty cookie, keeping it
// consistent makes the logout output byte-identical to the original write.
//
// The CSRF cookie is deliberately NOT cleared here: it is written separately by
// SetCSRF, so it is cleared separately by ClearCSRF. A starter that never issues
// a CSRF cookie thus emits no stray CSRF Set-Cookie on logout.
func ClearSession(w http.ResponseWriter, o Options) {
	o = o.withDefaults()
	httpOnly := map[string]bool{
		o.JWTName:      true,
		o.UserIDName:   o.UserIDHttpOnly,
		o.DeadlineName: o.DeadlineHttpOnly,
		o.TimerName:    true,
	}
	for _, name := range []string{o.JWTName, o.UserIDName, o.DeadlineName, o.TimerName} {
		c := o.cookie(name, "", 0, httpOnly[name])
		c.MaxAge = -1
		http.SetCookie(w, c)
	}
	w.Header().Set(userContextHeaderName, "")
}

// ClearCSRF expires the CSRF-Token cookie (double-submit pattern). Call it
// alongside ClearSession on logout for starters that issue a CSRF cookie via
// SetCSRF; starters without CSRF simply never call it.
func ClearCSRF(w http.ResponseWriter, o Options) {
	o = o.withDefaults()
	c := o.cookie(o.CSRFName, "", 0, false) // readable, mirroring SetCSRF
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// SetCSRF writes the CSRF cookie using the supplied token.
//
// The cookie is deliberately NOT HttpOnly: this package implements the
// double-submit-cookie pattern, in which the SPA reads the CSRF cookie via
// JavaScript and echoes it back in the X-CSRF-Token request header. The server
// then compares the cookie value against the header value (see
// CSRFTokenFromRequest). A readable cookie is required for that to work and is
// safe because the token's only purpose is to prove same-origin script access;
// the sensitive JWT remains HttpOnly.
//
// If token is empty a cryptographically random token is generated.
func SetCSRF(w http.ResponseWriter, token string, o Options) string {
	o = o.withDefaults()
	if token == "" {
		token = NewCSRFToken()
	}
	c := o.cookie(o.CSRFName, token, maxAgeSeconds(o.CSRFMaxAge), false)
	http.SetCookie(w, c)
	return token
}

// CSRFTokenFromRequest returns the CSRF cookie value carried on the request, or
// the empty string if the cookie is absent. To validate a request, compare this
// value against CSRFHeaderFromRequest and reject when they differ or either is
// empty.
func CSRFTokenFromRequest(r *http.Request) string {
	c, err := r.Cookie(DefaultCSRFName)
	if err != nil {
		return ""
	}
	return c.Value
}

// CSRFTokenFromRequestNamed behaves like CSRFTokenFromRequest but uses a custom
// cookie name (matching Options.CSRFName).
func CSRFTokenFromRequestNamed(r *http.Request, name string) string {
	if name == "" {
		name = DefaultCSRFName
	}
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// CSRFHeaderFromRequest returns the X-CSRF-Token request header value, which the
// SPA echoes from the CSRF cookie for double-submit verification.
func CSRFHeaderFromRequest(r *http.Request) string {
	return r.Header.Get(csrfHeaderName)
}

// NewCSRFToken returns a 256-bit cryptographically random, URL-safe token.
func NewCSRFToken() string {
	b := make([]byte, 32)
	// crypto/rand.Read never returns a short read or error on supported
	// platforms; if it ever does, the resulting token would be all zeros, so
	// we surface that by panicking rather than minting a predictable token.
	if _, err := rand.Read(b); err != nil {
		panic("authcookies: failed to read random bytes for CSRF token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// SessionClaims is the user context published to downstream services and the
// SPA. It mirrors the claims emitted by the upstream auth codec.
type SessionClaims struct {
	UserSub string   `json:"user_sub"`
	Groups  []string `json:"groups,omitempty"`
}

// EncodeUserContextHeader serializes claims as base64(JSON) and sets the
// X-User-Context response header.
//
// SECURITY: this header is server-set and must be treated as trusted ONLY when
// it arrives from the gateway/edge that performed authentication. Downstream
// services must strip any inbound X-User-Context from untrusted clients before
// the gateway re-sets it; never trust a client-supplied value.
func EncodeUserContextHeader(w http.ResponseWriter, claims SessionClaims) error {
	payload, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	w.Header().Set(userContextHeaderName, base64.StdEncoding.EncodeToString(payload))
	return nil
}

// DecodeUserContextHeader parses the X-User-Context request header into
// SessionClaims. It returns an error if the header is missing or malformed.
//
// SECURITY: only call this on requests received from the trusted gateway. See
// EncodeUserContextHeader for the trust boundary.
func DecodeUserContextHeader(r *http.Request) (SessionClaims, error) {
	var claims SessionClaims
	raw := r.Header.Get(userContextHeaderName)
	if raw == "" {
		return claims, http.ErrNoCookie
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return claims, err
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return claims, err
	}
	return claims, nil
}

// cookie builds an *http.Cookie applying the shared Options attributes.
func (o Options) cookie(name, value string, maxAge int, httpOnly bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     o.Path,
		Domain:   o.Domain,
		HttpOnly: httpOnly,
		Secure:   o.Secure,
		SameSite: o.SameSite,
		MaxAge:   maxAge,
	}
}

// maxAgeSeconds converts a duration to whole seconds for http.Cookie.MaxAge.
// Non-positive durations yield 0, which net/http treats as a session cookie.
func maxAgeSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d / time.Second)
}

// fmtUnix formats t as a UTC Unix-seconds string. A zero time yields "0".
func fmtUnix(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.UTC().Unix(), 10)
}
