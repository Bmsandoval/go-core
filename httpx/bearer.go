package httpx

import (
	"net/http"
	"strings"
)

// BearerToken extracts the credential from an HTTP Authorization header of the
// form "Bearer <token>". The "Bearer" scheme is matched case-insensitively and
// surrounding whitespace on the token is trimmed. It returns "" when the header
// is absent, uses a different scheme, or carries no token.
//
// This is the shared form of the inline Authorization: Bearer parse the cognito
// starters use to accept desktop/native Bearer credentials alongside session
// cookies.
func BearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
