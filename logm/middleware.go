package logm

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/Bmsandoval/go-core/clientip"
	"go.uber.org/zap"
)

// requestIDHeader is the canonical header used to read an inbound request ID and
// to echo the resolved ID back on the response.
const requestIDHeader = "X-Request-Id"

// Middleware wraps next with request-scoped logging using the supplied base
// logger. For each request it:
//
//   - resolves a request ID (the inbound X-Request-Id header if present,
//     otherwise a new UUID) and echoes it on the response,
//   - injects a logger carrying request_id into the request context so
//     downstream handlers can log with logm.Log(r.Context()),
//   - wraps the ResponseWriter to capture the status code and bytes written,
//   - emits exactly one structured access-log line when the handler returns.
//
// Pass the *zap.Logger returned by New as the base logger.
func Middleware(base *zap.Logger) func(http.Handler) http.Handler {
	if base == nil {
		base = nop
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			requestID := r.Header.Get(requestIDHeader)
			if requestID == "" {
				requestID = uuid.NewString()
			}
			w.Header().Set(requestIDHeader, requestID)

			logger := base.With(zap.String("request_id", requestID))
			ctx := ToContext(r.Context(), logger)

			rw := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r.WithContext(ctx))

			logger.Info("request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", rw.status),
				zap.Duration("duration", time.Since(start)),
				zap.Int("bytes", rw.bytes),
				zap.String("client_ip", clientip.FromRequest(r)),
				zap.String("request_id", requestID),
			)
		})
	}
}

// responseRecorder is a minimal http.ResponseWriter wrapper that records the
// status code and number of bytes written so the access log can report them.
type responseRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

// WriteHeader records the status code before delegating. Repeat calls are
// ignored, matching net/http semantics.
func (r *responseRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.status = status
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(status)
}

// Write records the byte count and ensures a status is captured for handlers
// that write a body without an explicit WriteHeader call.
func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}
