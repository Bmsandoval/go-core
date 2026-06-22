// Package logm is the shared structured-logging package for go-core services.
//
// It wraps go.uber.org/zap with three concerns:
//
//   - Construction: New builds a *zap.Logger configured for either a
//     human-friendly development console or production JSON on stdout.
//   - Context plumbing: a logger (plus accumulated fields) can be carried on a
//     context.Context and extracted anywhere downstream without threading the
//     logger through every function signature.
//   - HTTP middleware: Middleware injects a request-scoped logger, propagates a
//     request ID, and emits one structured access-log line per request.
package logm

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Mode selects the logger's output style.
type Mode string

const (
	// Development renders human-friendly, colorized console output with caller
	// info and a DebugLevel default.
	Development Mode = "development"
	// Production renders structured JSON to stdout with an InfoLevel default,
	// suitable for ingestion by log aggregators.
	Production Mode = "production"
)

// options holds the resolved configuration for New. Callers mutate it through
// Option values rather than touching it directly.
type options struct {
	mode  Mode
	level zapcore.Level
	// levelSet records whether the caller pinned an explicit level; when false
	// New derives a sensible default from the mode.
	levelSet bool
}

// Option customizes logger construction. See WithMode and WithLevel.
type Option func(*options)

// WithMode selects Development or Production output. Defaults to Development.
func WithMode(m Mode) Option {
	return func(o *options) { o.mode = m }
}

// WithLevel pins the minimum enabled log level. When unset, Development
// defaults to DebugLevel and Production to InfoLevel.
func WithLevel(l zapcore.Level) Option {
	return func(o *options) {
		o.level = l
		o.levelSet = true
	}
}

// New constructs a *zap.Logger from the supplied options.
//
// In Development mode it uses the package's pretty console encoder (see
// encoder_pretty.go) writing to stdout — no external pretty-printing
// dependency. In Production mode it emits JSON to stdout with ISO-8601
// timestamps and short caller paths.
func New(opts ...Option) (*zap.Logger, error) {
	cfg := options{mode: Development}
	for _, opt := range opts {
		opt(&cfg)
	}

	if !cfg.levelSet {
		cfg.level = zapcore.DebugLevel
		if cfg.mode == Production {
			cfg.level = zapcore.InfoLevel
		}
	}

	if cfg.mode == Production {
		zc := zap.NewProductionConfig()
		zc.Level = zap.NewAtomicLevelAt(cfg.level)
		zc.EncoderConfig.TimeKey = "timestamp"
		zc.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		zc.EncoderConfig.CallerKey = "caller"
		zc.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
		return zc.Build(zap.AddCaller())
	}

	ec := zap.NewDevelopmentEncoderConfig()
	ec.TimeKey = "timestamp"
	ec.EncodeTime = zapcore.ISO8601TimeEncoder
	ec.LevelKey = "level"
	ec.MessageKey = "msg"
	ec.CallerKey = "caller"
	ec.EncodeCaller = zapcore.ShortCallerEncoder

	core := zapcore.NewCore(newPrettyEncoder(ec), zapcore.AddSync(os.Stdout), cfg.level)
	return zap.New(core, zap.AddCaller()), nil
}
