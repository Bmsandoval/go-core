package cognito

import "testing"

func TestSanitizeReturnTo(t *testing.T) {
	const fb = "/"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"normal path kept", "/app/settings?x=1#h", "/app/settings?x=1#h"},
		{"root kept", "/", "/"},
		{"empty -> fallback", "", fb},
		{"relative -> fallback", "app/x", fb},
		{"protocol-relative", "//evil.com", fb},
		{"backslash trick", "/\\evil.com", fb},
		{"scheme in path", "/x://evil", fb},
		{"absolute url", "https://evil.com", fb},
		{"encoded protocol-relative lower", "/%2f%2fevil.com", fb},
		{"encoded protocol-relative upper", "/%2F%2Fevil.com", fb},
		{"encoded backslash", "/%5cevil.com", fb},
		{"control char", "/foo\nbar", fb},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SanitizeReturnTo(c.in, fb); got != c.want {
				t.Fatalf("SanitizeReturnTo(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestEncodeParseStateRoundTrip(t *testing.T) {
	nonce, err := RandomNonce()
	if err != nil {
		t.Fatalf("RandomNonce: %v", err)
	}
	raw, err := EncodeState("/app/dashboard", nonce)
	if err != nil {
		t.Fatalf("EncodeState: %v", err)
	}
	got, err := ParseState(raw)
	if err != nil {
		t.Fatalf("ParseState: %v", err)
	}
	if got.Nonce != nonce {
		t.Fatalf("nonce round-trip: got %q want %q", got.Nonce, nonce)
	}
}
