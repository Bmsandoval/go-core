package cognito

import (
	"net/http"
	"testing"
	"time"
)

func TestNewClients(t *testing.T) {
	cfg := Config{
		Region:      "us-east-1",
		UserPoolID:  "us-east-1_abc123",
		ClientID:    "client-id",
		Domain:      "myapp",
		RedirectURI: "http://localhost:5173/auth/redirect",
	}
	hc := &http.Client{Timeout: 5 * time.Second}

	v, o := NewClients(cfg, hc, time.Hour)
	if v == nil {
		t.Fatal("NewClients returned nil Validator")
	}
	if o == nil {
		t.Fatal("NewClients returned nil OAuthClient")
	}

	// Both clients must be built from the same cfg: spot-check via cfg-derived URLs.
	if got := o.AuthorizeURL(""); got == "" {
		t.Fatal("OAuthClient built without usable cfg (empty AuthorizeURL)")
	}
	if v.cfg != cfg {
		t.Fatalf("Validator built with unexpected cfg: %+v", v.cfg)
	}
	if o.cfg != cfg {
		t.Fatalf("OAuthClient built with unexpected cfg: %+v", o.cfg)
	}

	// Nil httpClient must be tolerated (mirrors the starters passing a nil seam).
	if v2, o2 := NewClients(cfg, nil, 0); v2 == nil || o2 == nil {
		t.Fatal("NewClients(nil httpClient) returned a nil client")
	}
}

func TestFeaturesFromGroups(t *testing.T) {
	cases := []struct {
		name   string
		groups []string
		want   map[string]bool
	}{
		{"nil -> empty", nil, map[string]bool{}},
		{"empty -> empty", []string{}, map[string]bool{}},
		{"single", []string{"admin"}, map[string]bool{"admin": true}},
		{
			"multi",
			[]string{"admin", "beta", "billing"},
			map[string]bool{"admin": true, "beta": true, "billing": true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FeaturesFromGroups(c.groups)
			if got == nil {
				t.Fatal("FeaturesFromGroups returned nil map")
			}
			if len(got) != len(c.want) {
				t.Fatalf("FeaturesFromGroups = %v, want %v", got, c.want)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Fatalf("FeaturesFromGroups[%q] = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}
