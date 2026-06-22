package cognito

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testPKCEConfig() Config {
	return Config{
		Region:      "us-east-1",
		UserPoolID:  "us-east-1_xpool",
		ClientID:    "client123",
		Domain:      "myapp",
		RedirectURI: "https://app.example.com/cb",
	}
}

// RFC 7636 Appendix B known-answer vector.
func TestCodeChallengeS256_RFC7636Vector(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := CodeChallengeS256(verifier); got != want {
		t.Fatalf("CodeChallengeS256 = %q, want %q", got, want)
	}
}

func TestGeneratePKCEVerifier(t *testing.T) {
	v1, err := GeneratePKCEVerifier()
	if err != nil {
		t.Fatalf("GeneratePKCEVerifier: %v", err)
	}
	v2, _ := GeneratePKCEVerifier()
	if v1 == "" || v1 == v2 {
		t.Fatalf("verifier should be random + non-empty: %q vs %q", v1, v2)
	}
	if len(v1) < 43 {
		t.Fatalf("verifier too short (%d); RFC 7636 wants 43-128", len(v1))
	}
	if strings.ContainsAny(v1, "+/=") {
		t.Fatalf("verifier must be URL-safe (no + / =): %q", v1)
	}
}

func TestAuthorizeURLPKCE(t *testing.T) {
	o := NewOAuthClient(testPKCEConfig(), nil)
	challenge := CodeChallengeS256("verifier-abc")
	u, err := url.Parse(o.AuthorizeURLPKCE("state-xyz", challenge))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasSuffix(u.Path, "/oauth2/authorize") {
		t.Errorf("path = %q, want .../oauth2/authorize", u.Path)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "client123",
		"redirect_uri":          "https://app.example.com/cb",
		"state":                 "state-xyz",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %q = %q, want %q", k, got, want)
		}
	}
}

type pkceRewriteTransport struct{ host string }

func (rt pkceRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = rt.host
	return http.DefaultTransport.RoundTrip(req)
}

func TestExchangeCodePKCE(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id_token":"idtok","access_token":"acctok","refresh_token":"reftok","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	client := &http.Client{Transport: pkceRewriteTransport{host: strings.TrimPrefix(srv.URL, "http://")}}
	o := NewOAuthClient(testPKCEConfig(), client)

	tok, err := o.ExchangeCodePKCE(context.Background(), "authcode", "verifier-abc")
	if err != nil {
		t.Fatalf("ExchangeCodePKCE: %v", err)
	}
	if tok.IDToken != "idtok" || tok.AccessToken != "acctok" || tok.RefreshToken != "reftok" {
		t.Fatalf("unexpected token response: %+v", tok)
	}
	want := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     "client123",
		"code":          "authcode",
		"code_verifier": "verifier-abc",
		"redirect_uri":  "https://app.example.com/cb",
	}
	for k, v := range want {
		if gotForm.Get(k) != v {
			t.Errorf("token form %q = %q, want %q", k, gotForm.Get(k), v)
		}
	}

	if _, err := o.ExchangeCodePKCE(context.Background(), "authcode", ""); err == nil {
		t.Fatalf("expected error for empty code_verifier")
	}
}

func TestUserInfo(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"abc","email":"u@example.com"}`))
	}))
	defer srv.Close()

	client := &http.Client{Transport: pkceRewriteTransport{host: strings.TrimPrefix(srv.URL, "http://")}}
	o := NewOAuthClient(testPKCEConfig(), client)

	claims, err := o.UserInfo(context.Background(), "acctok")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if claims["sub"] != "abc" || claims["email"] != "u@example.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if gotAuth != "Bearer acctok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer acctok")
	}
	if _, err := o.UserInfo(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty access token")
	}
}
