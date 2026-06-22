package httpx

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Bmsandoval/go-core/clientip"
)

// RateLimitOptions configures the per-client rate limiter.
type RateLimitOptions struct {
	// Limit is the maximum number of requests permitted per client within a
	// single Window. Values <= 0 disable limiting (every request is allowed).
	Limit int

	// Window is the length of the sliding window over which Limit is enforced.
	// Must be > 0; a non-positive value defaults to one minute.
	Window time.Duration

	// KeyFunc derives the client identity used for bucketing. When nil it
	// defaults to clientip.FromRequest, keying by the caller's IP address.
	KeyFunc func(r *http.Request) string

	// OnLimit handles requests that exceed the limit. When nil a default
	// handler is used that sets Retry-After and writes 429 Too Many Requests.
	OnLimit http.HandlerFunc

	// CleanupInterval controls how often the background janitor sweeps stale
	// client buckets. When <= 0 it defaults to max(Window, time.Minute). The
	// janitor is what prevents the unbounded-map memory leak present in the
	// source implementations, which never evicted idle clients.
	CleanupInterval time.Duration
}

// bucket holds the timestamps of recent requests for a single client. Access is
// guarded by Limiter.mu.
type bucket struct {
	hits []time.Time
}

// Limiter is a concurrency-safe, per-client sliding-window rate limiter. It owns
// a background janitor goroutine that evicts idle client buckets so the backing
// map cannot grow without bound. Always call Stop when the limiter is no longer
// needed to release the janitor.
type Limiter struct {
	limit    int
	window   time.Duration
	keyFunc  func(r *http.Request) string
	onLimit  http.HandlerFunc
	retryHdr string

	mu      sync.Mutex
	buckets map[string]*bucket

	stopOnce sync.Once
	stop     chan struct{}
}

// NewLimiter constructs a Limiter from opts and starts its janitor goroutine.
// The caller is responsible for invoking Stop to terminate the janitor.
func NewLimiter(opts RateLimitOptions) *Limiter {
	window := opts.Window
	if window <= 0 {
		window = time.Minute
	}

	keyFunc := opts.KeyFunc
	if keyFunc == nil {
		keyFunc = clientip.FromRequest
	}

	// Pre-compute the Retry-After value (whole seconds, at least 1).
	retrySecs := int(window / time.Second)
	if retrySecs < 1 {
		retrySecs = 1
	}
	retryHdr := strconv.Itoa(retrySecs)

	onLimit := opts.OnLimit
	if onLimit == nil {
		onLimit = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", retryHdr)
			http.Error(w, "too many requests", http.StatusTooManyRequests)
		}
	}

	cleanup := opts.CleanupInterval
	if cleanup <= 0 {
		cleanup = window
		if cleanup < time.Minute {
			cleanup = time.Minute
		}
	}

	l := &Limiter{
		limit:    opts.Limit,
		window:   window,
		keyFunc:  keyFunc,
		onLimit:  onLimit,
		retryHdr: retryHdr,
		buckets:  make(map[string]*bucket),
		stop:     make(chan struct{}),
	}

	go l.janitor(cleanup)
	return l
}

// allow records a request for key and reports whether it is within the limit.
// It prunes timestamps older than the window on every call (sliding window).
func (l *Limiter) allow(key string) bool {
	if l.limit <= 0 {
		return true
	}

	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil {
		b = &bucket{}
		l.buckets[key] = b
	}

	// Drop expired hits, compacting in place to avoid an allocation.
	kept := b.hits[:0]
	for _, t := range b.hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.hits = kept

	if len(b.hits) >= l.limit {
		return false
	}
	b.hits = append(b.hits, now)
	return true
}

// janitor periodically evicts buckets whose newest hit has aged out of the
// window, bounding the map to clients seen within roughly the last window. It
// exits when Stop is called.
func (l *Limiter) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-l.stop:
			return
		case now := <-ticker.C:
			cutoff := now.Add(-l.window)
			l.mu.Lock()
			for key, b := range l.buckets {
				// A bucket is stale when it has no hit newer than the cutoff.
				stale := true
				for _, t := range b.hits {
					if t.After(cutoff) {
						stale = false
						break
					}
				}
				if stale {
					delete(l.buckets, key)
				}
			}
			l.mu.Unlock()
		}
	}
}

// Stop halts the background janitor goroutine. It is safe to call multiple times
// and from multiple goroutines.
func (l *Limiter) Stop() {
	l.stopOnce.Do(func() { close(l.stop) })
}

// Middleware returns the rate-limiting middleware bound to this Limiter. The
// returned middleware may be reused across multiple routers; they share the
// same client buckets.
func (l *Limiter) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.allow(l.keyFunc(r)) {
				l.onLimit(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimit is a convenience constructor that builds a Limiter and returns its
// middleware together with a stop function. Callers who do not need to retain
// the *Limiter can use this directly:
//
//	mw, stop := httpx.RateLimit(httpx.RateLimitOptions{Limit: 100, Window: time.Minute})
//	defer stop()
//	r.Use(mw)
func RateLimit(opts RateLimitOptions) (Middleware, func()) {
	l := NewLimiter(opts)
	return l.Middleware(), l.Stop
}
