package cognito

import (
	"net/http"
	"time"
)

// NewClients builds a Validator and an OAuthClient from a single Config and a
// shared, injectable *http.Client. It is the pair-constructor that the starters
// previously inlined behind a per-config memo plus a test seam (a package-level
// testClient swapped in by SetHTTPClientForTest): both clients are always built
// together from the same cfg and httpClient.
//
// httpClient is passed through to both NewValidator (for JWKS fetches) and
// NewOAuthClient (for token-endpoint calls); pass nil to let each constructor
// use its default client. jwksTTL is forwarded to NewValidator (zero uses the
// package default).
func NewClients(cfg Config, httpClient *http.Client, jwksTTL time.Duration) (*Validator, *OAuthClient) {
	return NewValidator(cfg, httpClient, jwksTTL), NewOAuthClient(cfg, httpClient)
}

// FeaturesFromGroups maps Cognito group membership to a set of client feature
// flags. By the starter convention, each group enables a same-named feature.
// The result is always non-nil; a nil or empty groups slice yields an empty map.
//
// This is the shared port of the featuresFromGroups helper duplicated verbatim
// across the cognito starters' auth/session handlers.
func FeaturesFromGroups(groups []string) map[string]bool {
	features := make(map[string]bool, len(groups))
	for _, g := range groups {
		features[g] = true
	}
	return features
}
