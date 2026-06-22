package cognito

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// defaultJWKSTTL is how long a fetched JWK set is cached before a re-fetch.
// Cognito signing keys rotate rarely, so an hour balances freshness against
// avoiding a network round-trip on every token validation.
const defaultJWKSTTL = time.Hour

// defaultHTTPTimeout bounds every outbound HTTP call when a caller does not
// supply its own client.
const defaultHTTPTimeout = 10 * time.Second

// JWK is a single JSON Web Key as published by Cognito's JWKS endpoint.
type JWK struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

// JWKSet is the JSON document returned by the JWKS endpoint.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// cachedKeys is a TTL-bounded snapshot of the user pool's signing keys, indexed
// by key ID (kid).
type cachedKeys struct {
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

// jwksCache fetches and caches the user pool's RSA signing keys.
//
// A single in-flight fetch is shared across concurrent callers via the mutex:
// once one goroutine refreshes the cache, the others observe the fresh value
// rather than each issuing a redundant network request. This is the local
// equivalent of the shared cache.GetOrLoad single-fetch behaviour; a tiny
// internal cache is used here to keep go-core/cognito free of guesses about an
// external cache API.
type jwksCache struct {
	url        string
	ttl        time.Duration
	httpClient *http.Client

	mu     sync.Mutex
	cached *cachedKeys
}

// newJWKSCache builds a cache for the given JWKS URL. A zero ttl falls back to
// defaultJWKSTTL and a nil client falls back to a client with defaultHTTPTimeout.
func newJWKSCache(jwksURL string, ttl time.Duration, client *http.Client) *jwksCache {
	if ttl <= 0 {
		ttl = defaultJWKSTTL
	}
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &jwksCache{url: jwksURL, ttl: ttl, httpClient: client}
}

// keyForKid returns the RSA public key matching kid, fetching (and caching) the
// JWK set when the cache is empty or expired. It is safe for concurrent use.
func (c *jwksCache) keyForKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cached == nil || time.Now().After(c.cached.expiresAt) {
		fresh, err := c.fetch(ctx)
		if err != nil {
			return nil, err
		}
		c.cached = fresh
	}

	key, ok := c.cached.keys[kid]
	if !ok {
		return nil, fmt.Errorf("cognito: no signing key for kid %q", kid)
	}
	return key, nil
}

// fetch downloads the JWK set and decodes each key into an *rsa.PublicKey.
func (c *jwksCache) fetch(ctx context.Context) (*cachedKeys, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("cognito: build jwks request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cognito: fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return nil, fmt.Errorf("cognito: jwks endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var set JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("cognito: decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		pub, err := rsaPublicKeyFromJWK(k.E, k.N)
		if err != nil {
			return nil, fmt.Errorf("cognito: parse jwk %q: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}

	return &cachedKeys{keys: keys, expiresAt: time.Now().Add(c.ttl)}, nil
}

// rsaPublicKeyFromJWK reconstructs an RSA public key from the base64url-encoded
// modulus (n) and exponent (e) fields of a JWK.
func rsaPublicKeyFromJWK(rawE, rawN string) (*rsa.PublicKey, error) {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	// Left-pad the exponent to 4 bytes so it can be read as a big-endian uint32.
	if len(decodedE) < 4 {
		padded := make([]byte, 4)
		copy(padded[4-len(decodedE):], decodedE)
		decodedE = padded
	}

	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(decodedN),
		E: int(binary.BigEndian.Uint32(decodedE)),
	}, nil
}
