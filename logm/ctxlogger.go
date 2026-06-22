package logm

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// CtxLogger is a thin convenience wrapper binding a context to its logger so a
// caller can write logm.Ctx(ctx).Infof(...) without repeating FromContext.
//
// It deliberately exposes only the four common severities, each in a plain and
// a formatted (…f) variant. Structured key/value logging is intentionally NOT
// duplicated here: attach fields with logm.With(ctx, zap.String(...)) or call
// logm.Log(ctx).Info(msg, zap.Field...) directly. That keeps this type small
// and steers callers toward typed zap.Field values instead of a lossy
// string-only key/value API.
type CtxLogger struct {
	ctx context.Context
}

// Ctx binds ctx to a CtxLogger for fluent severity calls.
func Ctx(ctx context.Context) CtxLogger {
	return CtxLogger{ctx: ctx}
}

// The plain variants log a static message. AddCallerSkip(1) ensures the caller
// (not this wrapper) is reported as the log site.

// Debug logs msg at DebugLevel.
func (c CtxLogger) Debug(msg string) { c.log().Debug(msg) }

// Info logs msg at InfoLevel.
func (c CtxLogger) Info(msg string) { c.log().Info(msg) }

// Warn logs msg at WarnLevel.
func (c CtxLogger) Warn(msg string) { c.log().Warn(msg) }

// Error logs msg at ErrorLevel.
func (c CtxLogger) Error(msg string) { c.log().Error(msg) }

// The …f variants format the message with fmt.Sprintf semantics.

// Debugf logs a formatted message at DebugLevel.
func (c CtxLogger) Debugf(format string, args ...any) { c.log().Debug(fmt.Sprintf(format, args...)) }

// Infof logs a formatted message at InfoLevel.
func (c CtxLogger) Infof(format string, args ...any) { c.log().Info(fmt.Sprintf(format, args...)) }

// Warnf logs a formatted message at WarnLevel.
func (c CtxLogger) Warnf(format string, args ...any) { c.log().Warn(fmt.Sprintf(format, args...)) }

// Errorf logs a formatted message at ErrorLevel.
func (c CtxLogger) Errorf(format string, args ...any) { c.log().Error(fmt.Sprintf(format, args...)) }

// log resolves the context logger and adjusts the caller skip so log lines
// point at the caller of the CtxLogger method rather than this file.
func (c CtxLogger) log() *zap.Logger {
	return FromContext(c.ctx).WithOptions(zap.AddCallerSkip(1))
}
