package httpx

import (
	"net/http"
	"testing"
)

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string // "" means no Authorization header set
		set    bool
		want   string
	}{
		{"absent header", "", false, ""},
		{"empty header", "", true, ""},
		{"standard bearer", "Bearer abc.def.ghi", true, "abc.def.ghi"},
		{"lowercase scheme", "bearer abc", true, "abc"},
		{"uppercase scheme", "BEARER abc", true, "abc"},
		{"mixed-case scheme", "BeArEr abc", true, "abc"},
		{"extra spaces trimmed", "Bearer   abc  ", true, "abc"},
		{"scheme only no token", "Bearer ", true, ""},
		{"scheme only no space", "Bearer", true, ""},
		{"wrong scheme", "Basic abc", true, ""},
		{"token-like but no scheme", "abc", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if c.set {
				r.Header.Set("Authorization", c.header)
			}
			if got := BearerToken(r); got != c.want {
				t.Fatalf("BearerToken(%q) = %q, want %q", c.header, got, c.want)
			}
		})
	}
}

func TestBearerTokenNilRequest(t *testing.T) {
	if got := BearerToken(nil); got != "" {
		t.Fatalf("BearerToken(nil) = %q, want \"\"", got)
	}
}
