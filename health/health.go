// Package health provides HTTP handlers for liveness and readiness probes.
//
// Handler reports a simple liveness signal: if the process can serve the
// request at all, it is alive. Ready additionally runs a set of dependency
// checks (database connectivity, downstream services, and so on) and reports
// the service as unavailable when any of them fail.
package health

import (
	"context"
	"net/http"

	"github.com/Bmsandoval/go-core/respond"
)

// Handler returns a liveness handler that always responds with HTTP 200 and a
// JSON body of {"status":"ok","version":<version>}. The version field is
// omitted when version is empty.
func Handler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		respond.OK(w, statusBody{Status: "ok", Version: version})
	}
}

// statusBody is the liveness/readiness success payload.
type statusBody struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// Check is a named readiness probe. Probe should return nil when the dependency
// is healthy, or an error describing the failure. Name identifies the
// dependency in the readiness response (for example "database" or "cache").
type Check struct {
	// Name identifies the dependency in the readiness response body.
	Name string
	// Probe reports the dependency's health; nil means healthy. It should
	// honour the provided context's deadline and cancellation.
	Probe func(ctx context.Context) error
}

// readyFailure is the readiness response payload when one or more checks fail.
type readyFailure struct {
	Status string            `json:"status"`
	Errors map[string]string `json:"errors"`
}

// Ready returns a readiness handler that runs all provided checks using the
// request's context. If every check passes, it responds with HTTP 200 and
// {"status":"ok"}. If any check fails, it responds with HTTP 503 and
// {"status":"unavailable","errors":{<name>:<message>}}.
//
// Checks with a nil Probe are treated as healthy. Duplicate names collapse to a
// single entry in the errors map (the last failure wins).
func Ready(checks ...Check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		failures := make(map[string]string)
		for _, c := range checks {
			if c.Probe == nil {
				continue
			}
			if err := c.Probe(ctx); err != nil {
				failures[c.Name] = err.Error()
			}
		}

		if len(failures) > 0 {
			respond.JSON(w, http.StatusServiceUnavailable, readyFailure{
				Status: "unavailable",
				Errors: failures,
			})
			return
		}

		respond.OK(w, statusBody{Status: "ok"})
	}
}
