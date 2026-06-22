// Package cognito provides an AWS-SDK-free toolkit for working with Amazon
// Cognito User Pools over plain HTTPS: OAuth2 Hosted UI URL construction,
// authorization-code exchange, refresh-token rotation, and RS256 JWT
// validation against the pool's JWKS endpoint.
//
// The package depends only on the Go standard library and
// github.com/golang-jwt/jwt/v5. It deliberately avoids the AWS SDK so it can be
// embedded in lightweight services, CLIs, and desktop apps without pulling in
// the SDK's transitive dependency tree. Token refresh and code exchange are
// performed against Cognito's /oauth2/token endpoint rather than the
// InitiateAuth API.
package cognito

import (
	"fmt"
	"strings"
)

// Config holds the Cognito User Pool and app-client settings needed to build
// Hosted UI URLs, exchange/refresh tokens, and validate JWTs.
type Config struct {
	// Region is the AWS region of the user pool, e.g. "us-east-1".
	Region string
	// UserPoolID is the Cognito User Pool ID, e.g. "us-east-1_abc123".
	UserPoolID string
	// ClientID is the app-client ID (also the expected token audience).
	ClientID string
	// ClientSecret is the optional app-client secret. When set, token-endpoint
	// requests use HTTP Basic auth and a SECRET_HASH is computed.
	ClientSecret string
	// Domain is the Hosted UI domain. It accepts a bare prefix
	// ("myapp" -> "https://myapp.auth.<region>.amazoncognito.com"), a full host
	// ("auth.example.com"), or a full URL ("https://auth.example.com").
	Domain string
	// RedirectURI is the OAuth2 redirect (callback) URI registered with the app
	// client. It must match the value used at authorize time.
	RedirectURI string
}

// Configured reports whether the minimum fields required for JWT validation and
// token operations are present.
func (c Config) Configured() bool {
	return c.Region != "" && c.UserPoolID != "" && c.ClientID != ""
}

// Issuer returns the OIDC issuer (iss) claim value for the user pool.
func (c Config) Issuer() string {
	return fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", c.Region, c.UserPoolID)
}

// JWKSURL returns the JSON Web Key Set endpoint for the user pool.
func (c Config) JWKSURL() string {
	return c.Issuer() + "/.well-known/jwks.json"
}

// hostedBase normalizes Domain into an "https://<host>" base URL with no
// trailing slash. A bare prefix (no dot) expands to the standard Cognito
// Hosted UI host for the configured region.
func (c Config) hostedBase() string {
	domain := strings.TrimSpace(c.Domain)
	if domain == "" {
		return ""
	}
	if !strings.Contains(domain, ".") {
		return fmt.Sprintf("https://%s.auth.%s.amazoncognito.com", domain, c.Region)
	}
	if strings.HasPrefix(domain, "https://") || strings.HasPrefix(domain, "http://") {
		return strings.TrimSuffix(domain, "/")
	}
	return "https://" + strings.TrimSuffix(domain, "/")
}

// TokenURL returns the Hosted UI OAuth2 token endpoint.
func (c Config) TokenURL() string {
	return c.hostedBase() + "/oauth2/token"
}

// AuthorizeURL returns the Hosted UI OAuth2 authorize endpoint (no query string).
func (c Config) AuthorizeURL() string {
	return c.hostedBase() + "/oauth2/authorize"
}

// UserInfoURL returns the Hosted UI OIDC userInfo endpoint.
func (c Config) UserInfoURL() string {
	return c.hostedBase() + "/oauth2/userInfo"
}

// LogoutURLBase returns the Hosted UI logout endpoint (no query string).
func (c Config) LogoutURLBase() string {
	return c.hostedBase() + "/logout"
}
