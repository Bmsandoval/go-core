package httpx

import "net/http"

// Recoverer returns a middleware that recovers from panics in downstream
// handlers, preventing a single panicking request from crashing the server.
//
// When a panic is caught the optional onPanic callback is invoked with the
// request and the recovered value, giving the caller a hook to log the panic
// (and stack trace, which it may capture itself) using whatever logger it
// prefers. This package deliberately does NOT import a logging package, both to
// stay stdlib-only and to avoid an import cycle with packages that themselves
// depend on httpx.
//
// After the callback runs, a 500 Internal Server Error is written to the client
// — but only if nothing has been written yet is impossible to guarantee, so the
// handler relies on the standard library's behaviour: if the downstream handler
// already wrote a status, the WriteHeader call below is a no-op (logged by the
// stdlib) and the body write is best-effort.
//
// The http.ErrAbortHandler sentinel is re-panicked rather than swallowed, so the
// HTTP server can suppress its log line for intentionally aborted handlers, per
// the net/http convention.
func Recoverer(onPanic func(r *http.Request, err any)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				// Preserve net/http's intentional-abort semantics.
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				if onPanic != nil {
					onPanic(r, rec)
				}
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("internal server error\n"))
			}()

			next.ServeHTTP(w, r)
		})
	}
}
