// Package httpx provides small, dependency-free net/http middlewares that are
// safe to share across services. Every middleware in this package has the
// signature
//
//	type Middleware = func(http.Handler) http.Handler
//
// which is directly compatible with chi's Use without importing chi.
package httpx

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Middleware is the canonical net/http middleware type used throughout httpx.
// It is intentionally identical to chi's middleware shape, so values produced
// here can be passed to chi.Router.Use (or composed manually) without any
// adapter.
type Middleware = func(http.Handler) http.Handler

// CORSOptions configures the CORS middleware.
//
// Origin matching is resolved in this order:
//
//  1. If AllowOrigin is non-nil it is consulted first and is fully
//     authoritative.
//  2. Otherwise the request Origin must appear (exact, case-sensitive match)
//     in AllowedOrigins.
//
// Unlike the starter sources this middleware was distilled from, credentials
// are NOT hardcoded to true: set AllowCredentials explicitly. This matters
// because echoing an arbitrary origin together with
// Access-Control-Allow-Credentials: true is a well-known CORS misconfiguration.
type CORSOptions struct {
	// AllowedOrigins is the set of origins permitted via exact match. Ignored
	// when AllowOrigin is set. Use a single element of "*" to allow any origin
	// (only honoured when AllowCredentials is false, per the CORS spec).
	AllowedOrigins []string

	// AllowOrigin, when non-nil, is a predicate that decides whether a given
	// request Origin is permitted. It takes precedence over AllowedOrigins and
	// is useful for suffix/wildcard matching or dynamic allow-lists.
	AllowOrigin func(origin string) bool

	// AllowCredentials controls the Access-Control-Allow-Credentials header.
	// When true the wildcard "*" origin cannot be used; the concrete request
	// origin is echoed instead.
	AllowCredentials bool

	// AllowedMethods is advertised on preflight responses. Defaults to a common
	// REST set when empty.
	AllowedMethods []string

	// AllowedHeaders is advertised on preflight responses. Defaults to a common
	// set when empty.
	AllowedHeaders []string

	// MaxAge sets Access-Control-Max-Age, the duration a preflight result may be
	// cached by the browser. Values below one second are omitted.
	MaxAge time.Duration
}

var (
	defaultCORSMethods = []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions,
	}
	defaultCORSHeaders = []string{"Content-Type", "Authorization", "X-Requested-With"}
)

// CORS returns a middleware that applies the supplied cross-origin policy.
//
// The middleware always sets "Vary: Origin" so that shared caches do not serve
// a response generated for one origin to a request from another. The
// Access-Control-Allow-Origin header is only emitted when the request origin is
// permitted; disallowed cross-origin requests simply receive no CORS headers
// (and the browser blocks them). Preflight (OPTIONS) requests with an
// Access-Control-Request-Method header are answered with 204 and the configured
// method/header/max-age advertisements, and are not forwarded to next.
func CORS(opts CORSOptions) Middleware {
	// Pre-compute the exact-match lookup once at construction time.
	exact := make(map[string]bool, len(opts.AllowedOrigins))
	wildcard := false
	for _, o := range opts.AllowedOrigins {
		if o == "*" {
			wildcard = true
			continue
		}
		exact[o] = true
	}

	methods := opts.AllowedMethods
	if len(methods) == 0 {
		methods = defaultCORSMethods
	}
	allowMethods := strings.Join(methods, ", ")

	headers := opts.AllowedHeaders
	if len(headers) == 0 {
		headers = defaultCORSHeaders
	}
	allowHeaders := strings.Join(headers, ", ")

	var maxAge string
	if opts.MaxAge >= time.Second {
		maxAge = strconv.Itoa(int(opts.MaxAge / time.Second))
	}

	// allowed reports whether origin passes the configured policy.
	allowed := func(origin string) bool {
		if origin == "" {
			return false
		}
		if opts.AllowOrigin != nil {
			return opts.AllowOrigin(origin)
		}
		if exact[origin] {
			return true
		}
		// "*" only counts when credentials are not requested; with
		// credentials a concrete origin must be echoed instead.
		return wildcard && !opts.AllowCredentials
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Origin influences the response, so it must be part of the cache key.
			w.Header().Add("Vary", "Origin")

			if allowed(origin) {
				// When credentials are disallowed and a bare wildcard policy is
				// in effect we may answer with "*"; otherwise echo the concrete
				// origin (required when credentials are allowed).
				if wildcard && !opts.AllowCredentials && opts.AllowOrigin == nil && !exact[origin] {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
				if opts.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			// Handle the preflight request. A genuine preflight carries
			// Access-Control-Request-Method; we advertise policy and stop here.
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				h := w.Header()
				h.Add("Vary", "Access-Control-Request-Method")
				h.Add("Vary", "Access-Control-Request-Headers")
				h.Set("Access-Control-Allow-Methods", allowMethods)
				h.Set("Access-Control-Allow-Headers", allowHeaders)
				if maxAge != "" {
					h.Set("Access-Control-Max-Age", maxAge)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
