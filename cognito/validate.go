package cognito

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the normalized subset of Cognito JWT claims most callers need,
// together with the full decoded claim set in Raw for anything else.
type Claims struct {
	// Sub is the immutable user identifier (the "sub" claim).
	Sub string
	// Email is the user's email, when present.
	Email string
	// Name is a best-effort display name (name, else given+family, else email).
	Name string
	// EmailVerified reflects the email_verified claim (bool or "true"/"false").
	EmailVerified bool
	// Groups holds the cognito:groups membership, if any.
	Groups []string
	// TokenUse is the "token_use" claim: "id" or "access".
	TokenUse string
	// Raw is the full decoded claim map.
	Raw map[string]any
}

// Validator verifies Cognito RS256 JWTs against a user pool's JWKS, checking
// signature, issuer, expiry, token_use, and audience/client_id.
type Validator struct {
	cfg   Config
	jwks  *jwksCache
	clock func() time.Time
}

// NewValidator builds a Validator for cfg. An optional httpClient is used for
// JWKS fetches; pass nil to use a default client. jwksTTL of zero uses the
// package default. The JWK set is fetched lazily on first use and cached.
func NewValidator(cfg Config, httpClient *http.Client, jwksTTL time.Duration) *Validator {
	return &Validator{
		cfg:   cfg,
		jwks:  newJWKSCache(cfg.JWKSURL(), jwksTTL, httpClient),
		clock: time.Now,
	}
}

// Validate parses and fully validates tokenStr.
//
//   - wantUse constrains the "token_use" claim: "id", "access", or "" for either.
//   - requireFresh rejects expired tokens (and tokens whose iat is in the future);
//     pass false to permit expired tokens, e.g. before a refresh attempt.
//
// It verifies the RS256 signature using the cached JWKS (keyed by the token's
// kid), the issuer, and that the token's audience (aud) OR its client_id claim
// matches the configured ClientID. Access tokens carry client_id rather than
// aud, so accepting either lets one validator handle both token types.
func (v *Validator) Validate(ctx context.Context, tokenStr string, wantUse string, requireFresh bool) (*Claims, error) {
	if !v.cfg.Configured() {
		return nil, fmt.Errorf("cognito: validator is not configured")
	}

	keyFunc := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("cognito: unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("cognito: token missing kid header")
		}
		return v.jwks.keyForKid(ctx, kid)
	}

	// We validate audience and expiry manually (aud OR client_id; optional
	// freshness), so disable the parser's built-in checks for those.
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.cfg.Issuer()),
		jwt.WithTimeFunc(v.clock),
		jwt.WithoutClaimsValidation(),
	)

	mapClaims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(tokenStr, mapClaims, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("cognito: parse token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("cognito: token is not valid")
	}

	if err := v.validateIssuer(mapClaims); err != nil {
		return nil, err
	}
	if err := validateTokenUse(mapClaims, wantUse); err != nil {
		return nil, err
	}
	if err := v.validateAudienceOrClientID(mapClaims); err != nil {
		return nil, err
	}
	if err := v.validateExpiry(mapClaims, requireFresh); err != nil {
		return nil, err
	}

	return claimsFromMap(mapClaims), nil
}

func (v *Validator) validateIssuer(claims jwt.MapClaims) error {
	iss, _ := claims["iss"].(string)
	if iss != v.cfg.Issuer() {
		return fmt.Errorf("cognito: invalid issuer")
	}
	return nil
}

// validateAudienceOrClientID preserves timelord's fix: a token is accepted when
// EITHER the aud claim OR the client_id claim matches the configured ClientID.
func (v *Validator) validateAudienceOrClientID(claims jwt.MapClaims) error {
	want := v.cfg.ClientID
	if aud, _ := claims["aud"].(string); aud == want {
		return nil
	}
	// aud may also be encoded as an array.
	if rawAud, ok := claims["aud"].([]any); ok {
		for _, a := range rawAud {
			if s, _ := a.(string); s == want {
				return nil
			}
		}
	}
	if cid, _ := claims["client_id"].(string); cid == want {
		return nil
	}
	return fmt.Errorf("cognito: token audience/client_id does not match")
}

// validateExpiry enforces freshness when requireFresh is set: the token must not
// be expired and its issued-at (iat) must not be in the future.
func (v *Validator) validateExpiry(claims jwt.MapClaims, requireFresh bool) error {
	if !requireFresh {
		return nil
	}
	now := v.clock()

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return fmt.Errorf("cognito: token missing or invalid exp")
	}
	if !exp.After(now) {
		return fmt.Errorf("cognito: token is expired")
	}

	iat, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("cognito: token has invalid iat")
	}
	if iat != nil && iat.After(now.Add(time.Minute)) {
		// Small skew allowance; an iat well in the future is suspect.
		return fmt.Errorf("cognito: token issued in the future")
	}
	return nil
}

// validateTokenUse checks the token_use claim. An empty want accepts the two
// valid Cognito values ("id" or "access").
func validateTokenUse(claims jwt.MapClaims, want string) error {
	use, _ := claims["token_use"].(string)
	if want == "" {
		if use == "id" || use == "access" {
			return nil
		}
		return fmt.Errorf("cognito: token_use must be id or access")
	}
	if use != want {
		return fmt.Errorf("cognito: token_use must be %q", want)
	}
	return nil
}

// claimsFromMap projects the validated claim map into the Claims struct.
func claimsFromMap(claims jwt.MapClaims) *Claims {
	c := &Claims{Raw: map[string]any(claims)}
	c.Sub, _ = claims["sub"].(string)
	c.Email = EmailFromClaims(claims)
	c.Name = NameFromClaims(claims)
	c.EmailVerified = EmailVerifiedFromClaims(claims)
	c.Groups = GroupsFromClaims(claims)
	c.TokenUse, _ = claims["token_use"].(string)
	return c
}

// EmailFromClaims returns the "email" claim, or "" when absent.
func EmailFromClaims(claims map[string]any) string {
	email, _ := claims["email"].(string)
	return email
}

// EmailVerifiedFromClaims interprets the email_verified claim, which Cognito may
// encode as a bool or the strings "true"/"false".
func EmailVerifiedFromClaims(claims map[string]any) bool {
	switch v := claims["email_verified"].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

// NameFromClaims derives a display name: "name", else "given_name family_name",
// else the email.
func NameFromClaims(claims map[string]any) string {
	if name, _ := claims["name"].(string); name != "" {
		return name
	}
	if given, _ := claims["given_name"].(string); given != "" {
		if family, _ := claims["family_name"].(string); family != "" {
			return strings.TrimSpace(given + " " + family)
		}
		return given
	}
	return EmailFromClaims(claims)
}

// GroupsFromClaims extracts the cognito:groups membership, or nil when absent.
func GroupsFromClaims(claims map[string]any) []string {
	raw, ok := claims["cognito:groups"].([]any)
	if !ok {
		return nil
	}
	groups := make([]string, 0, len(raw))
	for _, g := range raw {
		if s, ok := g.(string); ok {
			groups = append(groups, s)
		}
	}
	if len(groups) == 0 {
		return nil
	}
	return groups
}
