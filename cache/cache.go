// Package cache provides a small, dependency-free, generic in-memory cache with
// per-entry TTL. It is intended for expensive, slow-changing reads (settings,
// reference data, resolved lookups) within a single process.
//
// Compared to a bare map it adds:
//
//   - Per-entry TTL set independently on every Set.
//   - Lazy eviction on Get plus an optional background janitor goroutine that
//     periodically purges expired entries, bounding memory for churning keys.
//   - An optional maximum size: when set and exceeded on Set, the entry with the
//     soonest expiry is evicted to make room.
//   - GetOrLoad with single-flight: concurrent misses for the same key call the
//     loader exactly once and share its result.
//   - An injectable clock for deterministic tests.
//
// All exported methods are safe for concurrent use. A nil *Cache behaves as a
// permanent miss so a component constructed without a cache transparently falls
// back to its underlying store; the sole exception is GetOrLoad, which still
// invokes the loader so callers always receive a value.
package cache

import (
	"context"
	"sync"
	"time"
)

// Cache is a concurrency-safe, generic in-memory cache whose entries expire
// after a per-entry TTL.
//
// The zero value is not usable; construct a Cache with New.
type Cache[K comparable, V any] struct {
	now     func() time.Time
	maxSize int // <= 0 means unbounded

	mu    sync.Mutex
	items map[K]item[V]

	// inflight tracks in-progress loads for GetOrLoad so that concurrent misses
	// for the same key share a single loader invocation. Guarded by mu.
	inflight map[K]*call[V]

	stop chan struct{}
	once sync.Once
}

type item[V any] struct {
	val V
	exp time.Time
}

// call represents a single in-flight loader invocation shared by all goroutines
// that missed on the same key concurrently.
type call[V any] struct {
	done chan struct{} // closed when the load completes
	val  V
	err  error
}

// Option configures a Cache constructed with New.
type Option[K comparable, V any] func(*Cache[K, V])

// WithClock overrides the time source used for expiry decisions. It is intended
// for tests; production code should rely on the default of time.Now. A nil fn is
// ignored.
func WithClock[K comparable, V any](fn func() time.Time) Option[K, V] {
	return func(c *Cache[K, V]) {
		if fn != nil {
			c.now = fn
		}
	}
}

// WithMaxSize bounds the number of live entries. When the cache is full and a
// Set introduces a new key, the entry whose expiry is soonest is evicted first.
// This approximates evicting the least useful entry, since soonest-to-expire
// entries are closest to becoming misses anyway. A value <= 0 means unbounded
// (the default).
//
// The bound is enforced only on insertion of a new key; updating an existing key
// never triggers eviction.
func WithMaxSize[K comparable, V any](n int) Option[K, V] {
	return func(c *Cache[K, V]) { c.maxSize = n }
}

// WithJanitor starts a background goroutine that purges expired entries every
// interval. The goroutine runs until Stop is called. A non-positive interval
// disables the janitor (the default), leaving eviction lazy.
func WithJanitor[K comparable, V any](interval time.Duration) Option[K, V] {
	return func(c *Cache[K, V]) {
		if interval > 0 {
			c.startJanitor(interval)
		}
	}
}

// New returns an empty cache configured by the given options.
func New[K comparable, V any](opts ...Option[K, V]) *Cache[K, V] {
	c := &Cache[K, V]{
		now:      time.Now,
		items:    make(map[K]item[V]),
		inflight: make(map[K]*call[V]),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Get returns the value stored under k and true if present and unexpired.
// Expired entries are removed lazily on access. A nil cache always misses.
func (c *Cache[K, V]) Get(k K) (V, bool) {
	var zero V
	if c == nil {
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[k]
	if !ok {
		return zero, false
	}
	if c.expired(it) {
		delete(c.items, k)
		return zero, false
	}
	return it.val, true
}

// Set stores v under k with the given ttl. A non-positive ttl stores the entry
// with an already-elapsed expiry, so it is treated as expired on the next
// access; callers wanting a live entry must pass ttl > 0. A nil cache is a no-op.
//
// If a maximum size is configured and inserting a new key would exceed it, the
// entry with the soonest expiry is evicted first.
func (c *Cache[K, V]) Set(k K, v V, ttl time.Duration) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(k, v, ttl)
}

// setLocked stores an entry. The caller must hold c.mu.
func (c *Cache[K, V]) setLocked(k K, v V, ttl time.Duration) {
	if _, exists := c.items[k]; !exists && c.maxSize > 0 {
		for len(c.items) >= c.maxSize {
			if !c.evictSoonestLocked() {
				break
			}
		}
	}
	c.items[k] = item[V]{val: v, exp: c.now().Add(ttl)}
}

// evictSoonestLocked removes the entry with the earliest expiry and reports
// whether an entry was removed. The caller must hold c.mu.
func (c *Cache[K, V]) evictSoonestLocked() bool {
	var (
		victim K
		found  bool
	)
	for k, it := range c.items {
		if !found || it.exp.Before(c.items[victim].exp) {
			victim, found = k, true
		}
	}
	if found {
		delete(c.items, victim)
	}
	return found
}

// Delete removes k. It is a no-op if k is absent or the cache is nil.
func (c *Cache[K, V]) Delete(k K) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.items, k)
	c.mu.Unlock()
}

// Len returns the number of entries currently held, including any that have
// expired but not yet been evicted. A nil cache reports 0.
func (c *Cache[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// GetOrLoad returns the cached value for k, or, on a miss, calls loader to
// produce it and caches the result under the given ttl. Loader errors are
// returned without being cached.
//
// Single-flight: when several goroutines miss on the same key concurrently,
// loader is invoked exactly once and every caller receives that shared result
// (or error). Different keys never block one another. The ctx passed to loader
// is the caller's; note that with single-flight the winning caller's ctx governs
// the shared load, so a follower's cancellation does not abort it.
//
// A nil cache still invokes loader (without caching) so callers always get a
// value or error.
func (c *Cache[K, V]) GetOrLoad(ctx context.Context, k K, ttl time.Duration, loader func(ctx context.Context) (V, error)) (V, error) {
	if c == nil {
		return loader(ctx)
	}

	c.mu.Lock()
	if it, ok := c.items[k]; ok && !c.expired(it) {
		c.mu.Unlock()
		return it.val, nil
	}

	// Join an in-flight load if one exists for this key.
	if cl, ok := c.inflight[k]; ok {
		c.mu.Unlock()
		<-cl.done
		return cl.val, cl.err
	}

	// We are the leader: register an in-flight call and run the loader.
	cl := &call[V]{done: make(chan struct{})}
	c.inflight[k] = cl
	c.mu.Unlock()

	cl.val, cl.err = loader(ctx)

	c.mu.Lock()
	delete(c.inflight, k)
	if cl.err == nil {
		c.setLocked(k, cl.val, ttl)
	}
	c.mu.Unlock()

	close(cl.done)
	return cl.val, cl.err
}

// expired reports whether it is at or past its expiry. The caller must hold
// c.mu.
func (c *Cache[K, V]) expired(it item[V]) bool {
	return !c.now().Before(it.exp)
}

// startJanitor launches the background eviction goroutine. It is idempotent:
// only the first call has any effect.
func (c *Cache[K, V]) startJanitor(interval time.Duration) {
	c.once.Do(func() {
		c.stop = make(chan struct{})
		go func() {
			t := time.NewTicker(interval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					c.evictExpired()
				case <-c.stop:
					return
				}
			}
		}()
	})
}

// evictExpired removes every expired entry. Used by the background janitor.
func (c *Cache[K, V]) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, it := range c.items {
		if c.expired(it) {
			delete(c.items, k)
		}
	}
}

// Stop halts the background janitor started via WithJanitor. It is safe to call
// multiple times and on a cache with no janitor or a nil cache.
func (c *Cache[K, V]) Stop() {
	if c == nil || c.stop == nil {
		return
	}
	select {
	case <-c.stop:
		// already stopped
	default:
		close(c.stop)
	}
}
