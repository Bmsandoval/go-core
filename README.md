# go-core

Shared, app-agnostic Go building blocks extracted from the prototyper Go
starters, the timelord backend, and ezsplit/defiant. Every package is meant to
drop into a chi/net-http + Cognito-style web backend with minimal coupling.

> **Status:** wired in. The leaf packages (`respond`, `logm`, `health`, `httpx`,
> `ids`) are consumed by all Go web starters; `migrate` and `cognito` wiring is
> underway (Stage 3b). See the playbook at `starters/docs/README.md`.

Module path: `github.com/Bmsandoval/go-core` · Go 1.25.

## Design principles

- **Router-agnostic.** Middleware is plain `func(http.Handler) http.Handler`
  (chi-compatible without importing chi). No chi/gorilla/go-kit dependency.
- **Driver-agnostic.** `migrate` takes a `*sql.DB`; no pgx/mysql/sqlite import.
- **AWS-SDK-free.** `cognito` does code-exchange *and* refresh over the Hosted-UI
  HTTPS token endpoint plus JWT/JWKS validation — no `aws-sdk-go-v2`.
- **Minimal deps:** `zap`, `golang-jwt/jwt/v5`, `google/uuid`, `cespare/xxhash/v2`,
  `go-playground/validator/v10`.
- No package-level mutable singletons; errors returned, not swallowed or panicked.

## Packages

| Package | Purpose | Notable improvements over the sources |
|---|---|---|
| `clientip` | Best-effort client IP from a request | One impl replacing 3 copied helpers; validates parsed IPs |
| `respond` | JSON response + error envelope helpers | Unified `{"error":{"code","message"}}`; buffers before `WriteHeader` so encode failures don't corrupt the response |
| `health` | Liveness handler + readiness probes | Adds `Ready(checks…)` with per-check 503 reporting |
| `ids` | Sortable ULIDs + prefixed ids | Returns the previously-ignored `rand` error; merges ULID + facm prefix styles |
| `cursor` | Keyset pagination cursors | Real errors instead of silent zero-value returns |
| `uuidx` | UUID binary/string/hex helpers | Length-validated, no panics |
| `hashing` | Non-cryptographic fast hash (xxhash) | Dropped the panicking low-entropy fake-UUID helper |
| `cache` | Generic in-memory TTL cache | Generics, single-flight `GetOrLoad`, janitor with `Stop()`, optional max-size, injectable clock |
| `cognito` | Hosted-UI OAuth, JWKS, JWT validation, OAuth `state`/returnTo | AWS-SDK-free refresh; JWKS TTL cache; aud-OR-client_id; URL-encoded params; encoded-open-redirect-safe `SanitizeReturnTo` |
| `migrate` | Embedded SQL migration runner | Driver-agnostic; `schema_migrations` tracking + checksums; dollar-quote/comment-aware statement splitter |
| `authcookies` | Session + CSRF cookies, `X-User-Context` | No env/config import — all behavior via `Options` |
| `httpx` | CORS, rate-limit, recover, request-scope middleware | Rate-limiter janitor fixes the unbounded-map leak; CORS no longer hardcodes `Allow-Credentials: true` |
| `logm` | Structured zap logging (ctx plumbing + HTTP access log) | Heavily trimmed merge of two sources: dropped CloudWatch core, grpc_ctxtags, go-kit, gorilla, and the external prettyconsole dep |
| `stripe` | Dependency-free Stripe client | context-aware, bounded retry/backoff, typed `APIError` instead of masking non-2xx |
| `validate` | Custom go-playground validators | Parameterized limits; dropped domain-specific rules; generic `OneOfFunc` |

## Using it from a starter

Today (pre-publication) consume it with a local `replace` directive. The
publish-&-version target is documented in `starters/docs/reference/module-distribution.md`.

```
// in a starter's go.mod
require github.com/Bmsandoval/go-core v0.0.0

replace github.com/Bmsandoval/go-core => ../packages/go-core
```

## Known follow-ups

- `cognito/jwks.go` ships a small internal TTL cache; it can be swapped for the
  shared `cache` package (localized to that one type).
- `migrate`'s tracking INSERT uses `?` placeholders by default; Postgres callers
  pass `migrate.WithPlaceholderStyle(migrate.PlaceholderDollar)`.

## Test

```
go test ./...        # unit tests
go test -race ./...  # concurrency-sensitive packages
```
