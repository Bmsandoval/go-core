package cognito

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// StatePayload is the decoded OAuth `state` value: a server-generated nonce for
// CSRF protection plus an optional, sanitized post-login returnTo path.
type StatePayload struct {
	// Nonce is the random CSRF token, compared against a value the server stored
	// out-of-band (e.g. a cookie).
	Nonce string `json:"n"`
	// ReturnTo is a sanitized same-origin path to redirect to after login.
	ReturnTo string `json:"rt,omitempty"`
}

// RandomNonce returns a URL-safe, cryptographically random nonce for use as the
// CSRF component of the OAuth state.
func RandomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// EncodeState builds an opaque, URL-safe OAuth state from returnTo and nonce.
// returnTo is sanitized before encoding so a hostile value can never round-trip.
func EncodeState(returnTo, nonce string) (string, error) {
	payload := StatePayload{Nonce: nonce, ReturnTo: SanitizeReturnTo(returnTo, "")}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ParseState decodes a state string produced by EncodeState. It rejects empty or
// nonce-less payloads and re-sanitizes ReturnTo defensively.
func ParseState(raw string) (StatePayload, error) {
	if raw == "" {
		return StatePayload{}, errors.New("cognito: missing state")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return StatePayload{}, err
	}
	var payload StatePayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return StatePayload{}, err
	}
	if payload.Nonce == "" {
		return StatePayload{}, errors.New("cognito: invalid state payload")
	}
	payload.ReturnTo = SanitizeReturnTo(payload.ReturnTo, "")
	return payload, nil
}

// SanitizeReturnTo returns value when it is a safe same-origin path, otherwise
// fallback. It guards against open redirects, including ones smuggled through a
// single layer of percent-encoding.
//
// A value is rejected when it:
//   - is empty,
//   - does not start with "/",
//   - is protocol-relative ("//host" or "/\host"),
//   - contains a scheme ("://"),
//   - contains control characters, or
//   - after one decode pass becomes any of the above (e.g. "/%2f%2fhost",
//     "/%2F", "/%5c", "/%09://").
//
// Only one decode pass is applied: browsers decode the URL once, so a value that
// is safe before AND after a single decode cannot be coerced into a cross-origin
// redirect by the browser.
func SanitizeReturnTo(value, fallback string) string {
	if isUnsafeReturnTo(value) {
		return fallback
	}
	// Defend against single-pass encoded payloads: decode once and re-check.
	if decoded, err := url.QueryUnescape(value); err == nil && decoded != value {
		if isUnsafeReturnTo(decoded) {
			return fallback
		}
	}
	return value
}

// isUnsafeReturnTo reports whether a raw path is unsafe to redirect to.
func isUnsafeReturnTo(value string) bool {
	if value == "" {
		return true
	}
	if containsControl(value) {
		return true
	}
	if !strings.HasPrefix(value, "/") {
		return true
	}
	// Protocol-relative forms, both with forward and back slash.
	if strings.HasPrefix(value, "//") || strings.HasPrefix(value, "/\\") {
		return true
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "://") {
		return true
	}
	return false
}

// containsControl reports whether s contains any ASCII control character
// (including NUL, tab, CR, LF, and DEL), which have no place in a redirect path
// and are a common header/URL smuggling vector.
func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
