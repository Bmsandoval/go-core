package cognito

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenResponse holds the tokens returned by Cognito's /oauth2/token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// OAuthClient performs Hosted UI URL construction and token-endpoint calls
// (code exchange, refresh) over plain HTTPS, with no AWS SDK dependency.
type OAuthClient struct {
	cfg        Config
	httpClient *http.Client
}

// NewOAuthClient builds an OAuthClient. Pass nil for httpClient to use a default
// client with a sensible timeout.
func NewOAuthClient(cfg Config, httpClient *http.Client) *OAuthClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &OAuthClient{cfg: cfg, httpClient: httpClient}
}

// defaultScopes are requested when building Hosted UI URLs.
const defaultScopes = "openid email profile"

// HostedLoginURL builds the Hosted UI login URL for the authorization-code flow.
// state is round-tripped for CSRF protection. An optional returnTo overrides the
// configured RedirectURI as the OAuth redirect_uri (it must be a registered
// callback URL). All parameters are URL-encoded.
func (o *OAuthClient) HostedLoginURL(state string, returnTo ...string) string {
	return o.hostedURL("/login", state, returnTo...)
}

// HostedSignupURL builds the Hosted UI signup URL, mirroring HostedLoginURL.
func (o *OAuthClient) HostedSignupURL(state string, returnTo ...string) string {
	return o.hostedURL("/signup", state, returnTo...)
}

// AuthorizeURL builds the standard OAuth2 /oauth2/authorize URL.
func (o *OAuthClient) AuthorizeURL(state string, returnTo ...string) string {
	return o.hostedURL("/oauth2/authorize", state, returnTo...)
}

func (o *OAuthClient) hostedURL(path, state string, returnTo ...string) string {
	redirect := o.cfg.RedirectURI
	if len(returnTo) > 0 && returnTo[0] != "" {
		redirect = returnTo[0]
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", o.cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", defaultScopes)
	if state != "" {
		q.Set("state", state)
	}
	return o.cfg.hostedBase() + path + "?" + q.Encode()
}

// LogoutURL builds the Hosted UI logout URL. logoutRedirect, when non-empty,
// sets logout_uri so Cognito returns the user to that registered sign-out URL.
func (o *OAuthClient) LogoutURL(logoutRedirect string) string {
	q := url.Values{}
	q.Set("client_id", o.cfg.ClientID)
	if logoutRedirect != "" {
		q.Set("logout_uri", logoutRedirect)
	}
	return o.cfg.LogoutURLBase() + "?" + q.Encode()
}

// ExchangeCode trades an authorization code for tokens via the
// authorization_code grant. redirectURI defaults to the configured RedirectURI;
// it must match the value used at authorize time. When a ClientSecret is set,
// HTTP Basic auth is used.
func (o *OAuthClient) ExchangeCode(ctx context.Context, code string, redirectURI ...string) (*TokenResponse, error) {
	if code == "" {
		return nil, fmt.Errorf("cognito: authorization code is empty")
	}
	redirect := o.cfg.RedirectURI
	if len(redirectURI) > 0 && redirectURI[0] != "" {
		redirect = redirectURI[0]
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", o.cfg.ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirect)

	return o.postToken(ctx, form)
}

// RefreshTokens renews tokens via the refresh_token grant over HTTPS — no AWS
// SDK and no username required. Cognito returns a fresh access_token and
// id_token; the refresh_token is typically not re-issued, so callers should
// retain the existing one when the response omits it.
func (o *OAuthClient) RefreshTokens(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("cognito: refresh token is empty")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", o.cfg.ClientID)
	form.Set("refresh_token", refreshToken)

	return o.postToken(ctx, form)
}

// postToken POSTs a form to the token endpoint and decodes the response. When a
// ClientSecret is configured it is applied via HTTP Basic auth (the form is not
// also stuffed with client_secret); a SECRET_HASH is added when a username is
// derivable, which the Hosted UI grants do not require but some pool configs do.
func (o *OAuthClient) postToken(ctx context.Context, form url.Values) (*TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("cognito: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if o.cfg.ClientSecret != "" {
		// Confidential client: authenticate with HTTP Basic per the OAuth2 spec.
		req.SetBasicAuth(url.QueryEscape(o.cfg.ClientID), url.QueryEscape(o.cfg.ClientSecret))
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cognito: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("cognito: read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to surface the structured OAuth error before falling back to raw.
		var oauthErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, fmt.Errorf("cognito: token endpoint %d: %s: %s", resp.StatusCode, oauthErr.Error, oauthErr.Description)
		}
		return nil, fmt.Errorf("cognito: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var out TokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cognito: decode token response: %w", err)
	}
	// Fail closed: a 200 with no access_token is not a usable success. Cognito's
	// code/refresh grants always return one; treat its absence as an error rather
	// than handing back a token-less response a caller might mistake for success.
	if out.AccessToken == "" {
		return nil, fmt.Errorf("cognito: token response contained no access_token")
	}
	return &out, nil
}

// SecretHash computes the Cognito SECRET_HASH for a username, as
// base64(HMAC-SHA256(username+clientID, clientSecret)). Exposed for callers that
// drive non-Hosted-UI flows requiring it.
func SecretHash(username, clientID, clientSecret string) string {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(username + clientID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// --- PKCE (RFC 7636) — for public clients (native/desktop/SPA) ---------------
//
// Public clients can't keep a client secret, so they protect the
// authorization-code exchange with PKCE: generate a high-entropy verifier, send
// its SHA-256 (S256) challenge on the authorize request, then present the
// verifier at token exchange. Usage:
//
//	verifier, _ := cognito.GeneratePKCEVerifier()
//	url := client.AuthorizeURLPKCE(state, cognito.CodeChallengeS256(verifier))
//	// ... user authorizes, you receive `code` ...
//	tokens, err := client.ExchangeCodePKCE(ctx, code, verifier)

// GeneratePKCEVerifier returns a cryptographically random RFC 7636 code_verifier
// (43 URL-safe chars from 32 random bytes).
func GeneratePKCEVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cognito: generate pkce verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CodeChallengeS256 derives the S256 code_challenge for a verifier:
// base64url(sha256(verifier)), no padding.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthorizeURLPKCE builds the /oauth2/authorize URL for the PKCE
// authorization-code flow. codeChallenge is the S256 hash of the verifier the
// caller will present at ExchangeCodePKCE. state is round-tripped; an optional
// returnTo overrides the configured redirect_uri (must be a registered callback).
// All params are URL-encoded.
func (o *OAuthClient) AuthorizeURLPKCE(state, codeChallenge string, returnTo ...string) string {
	redirect := o.cfg.RedirectURI
	if len(returnTo) > 0 && returnTo[0] != "" {
		redirect = returnTo[0]
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", o.cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", defaultScopes)
	if state != "" {
		q.Set("state", state)
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	return o.cfg.AuthorizeURL() + "?" + q.Encode()
}

// ExchangeCodePKCE trades an authorization code for tokens using PKCE: the
// code_verifier proves possession of the earlier code_challenge. Works for public
// clients with no secret; when a ClientSecret is configured it is also applied via
// HTTP Basic. redirectURI defaults to the configured RedirectURI and must match
// the value used at authorize time.
func (o *OAuthClient) ExchangeCodePKCE(ctx context.Context, code, codeVerifier string, redirectURI ...string) (*TokenResponse, error) {
	if code == "" {
		return nil, fmt.Errorf("cognito: authorization code is empty")
	}
	if codeVerifier == "" {
		return nil, fmt.Errorf("cognito: code verifier is empty")
	}
	redirect := o.cfg.RedirectURI
	if len(redirectURI) > 0 && redirectURI[0] != "" {
		redirect = redirectURI[0]
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", o.cfg.ClientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("code_verifier", codeVerifier)

	return o.postToken(ctx, form)
}

// UserInfo fetches the OIDC userInfo claims for an access token from the Hosted
// UI /oauth2/userInfo endpoint. Useful when an access token lacks profile claims
// (e.g. email) needed to provision a user. The access token is sent as a Bearer
// credential; a non-2xx response is returned as an error.
func (o *OAuthClient) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("cognito: access token is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.cfg.UserInfoURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("cognito: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cognito: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("cognito: read userinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cognito: userinfo endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cognito: decode userinfo response: %w", err)
	}
	return out, nil
}
