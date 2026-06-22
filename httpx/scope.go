package httpx

import (
	"context"
	"net/http"
	"sync"
)

// scopeKeyType is an unexported context-key type so that the scope value cannot
// collide with keys set by other packages.
type scopeKeyType struct{}

var scopeKey = scopeKeyType{}

// scope is a per-request memo store: a concurrency-safe map living for the
// duration of a single request. It is concurrency-safe because a handler may
// fan out into goroutines that share the same request context.
type scope struct {
	mu sync.RWMutex
	m  map[any]any
}

// RequestScope returns a middleware that attaches a fresh, empty memo store to
// each request's context.
//
// Use case: within the handling of one request the same expensive lookup (an
// authenticated user record, a feature-flag snapshot, a tenant config, …) is
// often needed in several places — handler, services, nested middleware. A
// process-wide cache risks cross-request staleness; recomputing wastes work.
// The request scope is the middle ground: a memo that is guaranteed fresh
// because it lives and dies with a single request, while still deduplicating
// repeat reads within that request.
//
// Pair it with Memo, ScopeGet, and ScopeSet.
func RequestScope() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := &scope{m: make(map[any]any)}
			ctx := context.WithValue(r.Context(), scopeKey, s)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// fromContext extracts the scope attached by RequestScope, if any.
func fromContext(ctx context.Context) (*scope, bool) {
	s, ok := ctx.Value(scopeKey).(*scope)
	return s, ok
}

// ScopeSet stores value under key in the request scope carried by ctx. It is a
// no-op (returns false) when ctx has no scope attached, e.g. because
// RequestScope was not installed for this route.
func ScopeSet(ctx context.Context, key, value any) bool {
	s, ok := fromContext(ctx)
	if !ok {
		return false
	}
	s.mu.Lock()
	s.m[key] = value
	s.mu.Unlock()
	return true
}

// ScopeGet retrieves the value stored under key in the request scope carried by
// ctx. The second return value reports whether a value was present (and whether
// a scope exists at all).
//
// T is the expected type of the stored value; if the stored value is not a T,
// the zero value and false are returned.
func ScopeGet[T any](ctx context.Context, key any) (T, bool) {
	var zero T
	s, ok := fromContext(ctx)
	if !ok {
		return zero, false
	}
	s.mu.RLock()
	raw, present := s.m[key]
	s.mu.RUnlock()
	if !present {
		return zero, false
	}
	v, ok := raw.(T)
	if !ok {
		return zero, false
	}
	return v, true
}

// Memo returns the value stored under key in ctx's request scope, computing and
// caching it via compute on the first call within the request. Subsequent calls
// with the same key return the memoized value without re-running compute.
//
// If compute returns an error the result is NOT cached, so a later call may
// retry. When ctx carries no request scope, Memo degrades gracefully: it simply
// runs compute every time and returns its result uncached.
//
// Memo holds no lock while compute runs, so two goroutines racing on the same
// missing key may both execute compute; the last writer wins. This keeps a slow
// compute from blocking unrelated keys. If single-flight semantics are required,
// callers should coordinate externally.
func Memo[T any](ctx context.Context, key any, compute func() (T, error)) (T, error) {
	if v, ok := ScopeGet[T](ctx, key); ok {
		return v, nil
	}
	v, err := compute()
	if err != nil {
		var zero T
		return zero, err
	}
	ScopeSet(ctx, key, v)
	return v, nil
}
