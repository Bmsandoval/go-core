package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGetOrLoadSingleFlight(t *testing.T) {
	c := New[string, int]()
	var calls atomic.Int64
	loader := func(ctx context.Context) (int, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond) // hold the flight open so others coalesce
		return 42, nil
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			v, err := c.GetOrLoad(context.Background(), "k", time.Minute, loader)
			if err != nil || v != 42 {
				t.Errorf("GetOrLoad = (%d,%v), want (42,nil)", v, err)
			}
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("loader called %d times, want exactly 1 (single-flight)", got)
	}
}

func TestSetGetExpiry(t *testing.T) {
	c := New[string, string]()
	c.Set("a", "v", time.Minute)
	if v, ok := c.Get("a"); !ok || v != "v" {
		t.Fatalf("Get(a) = (%q,%v), want (v,true)", v, ok)
	}
	c.Set("b", "x", time.Nanosecond)
	time.Sleep(time.Millisecond)
	if _, ok := c.Get("b"); ok {
		t.Fatal("expected b to be expired")
	}
}
