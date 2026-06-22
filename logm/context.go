package logm

import (
	"context"

	"go.uber.org/zap"
)

// ctxKey is an unexported context key type, ensuring this package's value never
// collides with keys set by other packages.
type ctxKey struct{}

// loggerKey is the singleton key under which the request-scoped logger is stored.
var loggerKey = ctxKey{}

// nop is returned by FromContext when no logger is present so callers never have
// to nil-check and a stray log call is always safe.
var nop = zap.NewNop()

// ToContext returns a copy of ctx carrying logger. Pass nil for logger to fall
// back to a no-op logger rather than storing nil.
func ToContext(ctx context.Context, logger *zap.Logger) context.Context {
	if logger == nil {
		logger = nop
	}
	return context.WithValue(ctx, loggerKey, logger)
}

// FromContext returns the logger stored on ctx, or a no-op logger when none is
// present. It never returns nil and never panics.
func FromContext(ctx context.Context) *zap.Logger {
	if ctx != nil {
		if l, ok := ctx.Value(loggerKey).(*zap.Logger); ok && l != nil {
			return l
		}
	}
	return nop
}

// With returns a copy of ctx whose logger has fields permanently attached. All
// subsequent FromContext/Log calls on the returned context (and its children)
// observe the accumulated fields.
//
// Unlike a mutating field accumulator, this is immutable: fields added on a
// derived context never leak back to the parent, which matches the semantics of
// context.WithValue and avoids data races across goroutines.
func With(ctx context.Context, fields ...zap.Field) context.Context {
	if len(fields) == 0 {
		return ctx
	}
	return ToContext(ctx, FromContext(ctx).With(fields...))
}

// Log returns the logger bound to ctx. It is a convenience alias for
// FromContext that reads naturally at call sites: logm.Log(ctx).Info("...").
func Log(ctx context.Context) *zap.Logger {
	return FromContext(ctx)
}
