package authcookies

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func cookies(t *testing.T, set func(w http.ResponseWriter)) map[string]*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	set(rec)
	res := &http.Response{Header: rec.Header()}
	out := map[string]*http.Cookie{}
	for _, c := range res.Cookies() {
		out[c.Name] = c
	}
	return out
}

// The load-bearing security property: a two-tier session writes the JWT/UserID/
// Timer cookies at the short TokenMaxAge and SessionDeadline at the long
// DeadlineMaxAge — so the bearer-token cookie never outlives its window.
func TestTwoTierMaxAge(t *testing.T) {
	got := cookies(t, func(w http.ResponseWriter) {
		SetSession(w, SessionParams{
			JWT:            "tok",
			UserID:         "sub-1",
			Deadline:       time.Unix(1700000000, 0),
			TokenMaxAge:    30 * time.Minute,
			DeadlineMaxAge: 24 * time.Hour,
		}, Default())
	})
	want := map[string]int{
		DefaultJWTName:      1800,
		DefaultUserIDName:   1800,
		DefaultTimerName:    1800,
		DefaultDeadlineName: 86400,
	}
	for name, age := range want {
		c, ok := got[name]
		if !ok {
			t.Fatalf("cookie %s not set", name)
		}
		if c.MaxAge != age {
			t.Errorf("%s MaxAge = %d, want %d", name, c.MaxAge, age)
		}
	}
}

// The SessionTimer cookie VALUE must carry the soft-timeout instant (Timer),
// not the absolute Deadline — the two-tier regression we are guarding against.
func TestTimerValueDistinctFromDeadline(t *testing.T) {
	timer := time.Unix(1700001800, 0)    // now + 30m
	deadline := time.Unix(1700086400, 0) // now + 24h
	got := cookies(t, func(w http.ResponseWriter) {
		SetSession(w, SessionParams{JWT: "t", UserID: "u", Timer: timer, Deadline: deadline}, Default())
	})
	if got[DefaultTimerName].Value != "1700001800" {
		t.Errorf("SessionTimer value = %q, want soft-timeout 1700001800 (not deadline)", got[DefaultTimerName].Value)
	}
	if got[DefaultDeadlineName].Value != "1700086400" {
		t.Errorf("SessionDeadline value = %q, want 1700086400", got[DefaultDeadlineName].Value)
	}
}

// Back-compat: an unset Timer falls back to Deadline (single-tier callers).
func TestTimerFallsBackToDeadline(t *testing.T) {
	deadline := time.Unix(1700086400, 0)
	got := cookies(t, func(w http.ResponseWriter) {
		SetSession(w, SessionParams{JWT: "t", UserID: "u", Deadline: deadline}, Default())
	})
	if got[DefaultTimerName].Value != "1700086400" {
		t.Errorf("SessionTimer value = %q, want deadline fallback 1700086400", got[DefaultTimerName].Value)
	}
}

// Back-compat: with only MaxAge set, every session cookie gets it (single tier).
func TestSingleTierBackCompat(t *testing.T) {
	got := cookies(t, func(w http.ResponseWriter) {
		SetSession(w, SessionParams{JWT: "t", UserID: "u", MaxAge: time.Hour}, Default())
	})
	for _, name := range []string{DefaultJWTName, DefaultUserIDName, DefaultTimerName, DefaultDeadlineName} {
		if got[name].MaxAge != 3600 {
			t.Errorf("%s MaxAge = %d, want 3600", name, got[name].MaxAge)
		}
	}
}

// HttpOnly: defaults keep UserID/Deadline readable (SPA); the opt-in flags lock them.
func TestHttpOnlyOptions(t *testing.T) {
	def := cookies(t, func(w http.ResponseWriter) {
		SetSession(w, SessionParams{JWT: "t", UserID: "u"}, Default())
	})
	if def[DefaultUserIDName].HttpOnly || def[DefaultDeadlineName].HttpOnly {
		t.Error("UserID/Deadline should be readable by default")
	}
	if !def[DefaultJWTName].HttpOnly || !def[DefaultTimerName].HttpOnly {
		t.Error("JWT/Timer must always be HttpOnly")
	}

	o := Default()
	o.UserIDHttpOnly = true
	o.DeadlineHttpOnly = true
	locked := cookies(t, func(w http.ResponseWriter) {
		SetSession(w, SessionParams{JWT: "t", UserID: "u"}, o)
	})
	if !locked[DefaultUserIDName].HttpOnly || !locked[DefaultDeadlineName].HttpOnly {
		t.Error("UserID/Deadline should be HttpOnly when opted in")
	}
}

// ClearSession expires exactly the 4 session cookies (NOT CSRF) with the same
// HttpOnly posture they were set with, so logout is byte-identical to the write.
func TestClearSessionNoCSRF(t *testing.T) {
	o := Default()
	o.UserIDHttpOnly = true // SetSession posture: UserID HttpOnly, Deadline readable
	got := cookies(t, func(w http.ResponseWriter) { ClearSession(w, o) })
	if _, ok := got[DefaultCSRFName]; ok {
		t.Error("ClearSession must not emit a CSRF-Token cookie")
	}
	want := map[string]bool{
		DefaultJWTName:      true,
		DefaultUserIDName:   true,  // o.UserIDHttpOnly
		DefaultDeadlineName: false, // o.DeadlineHttpOnly (default)
		DefaultTimerName:    true,
	}
	if len(got) != len(want) {
		t.Fatalf("cleared %d cookies, want %d: %v", len(got), len(want), got)
	}
	for name, ho := range want {
		c, ok := got[name]
		if !ok {
			t.Fatalf("cleared cookie %s missing", name)
		}
		if c.MaxAge != -1 {
			t.Errorf("%s MaxAge = %d, want -1", name, c.MaxAge)
		}
		if c.HttpOnly != ho {
			t.Errorf("%s cleared HttpOnly = %v, want %v", name, c.HttpOnly, ho)
		}
	}
}

// ClearCSRF expires only the CSRF cookie (readable), mirroring SetCSRF.
func TestClearCSRF(t *testing.T) {
	got := cookies(t, func(w http.ResponseWriter) { ClearCSRF(w, Default()) })
	c, ok := got[DefaultCSRFName]
	if !ok {
		t.Fatal("CSRF-Token not cleared")
	}
	if c.MaxAge != -1 || c.HttpOnly {
		t.Errorf("CSRF clear = {MaxAge:%d HttpOnly:%v}, want {-1 false}", c.MaxAge, c.HttpOnly)
	}
}

// CSRF: session cookie by default; persistent when CSRFMaxAge is set.
func TestCSRFMaxAge(t *testing.T) {
	sess := cookies(t, func(w http.ResponseWriter) { SetCSRF(w, "x", Default()) })
	if sess[DefaultCSRFName].MaxAge != 0 {
		t.Errorf("default CSRF MaxAge = %d, want 0 (session)", sess[DefaultCSRFName].MaxAge)
	}
	o := Default()
	o.CSRFMaxAge = 24 * time.Hour
	persist := cookies(t, func(w http.ResponseWriter) { SetCSRF(w, "x", o) })
	if persist[DefaultCSRFName].MaxAge != 86400 {
		t.Errorf("persistent CSRF MaxAge = %d, want 86400", persist[DefaultCSRFName].MaxAge)
	}
}
