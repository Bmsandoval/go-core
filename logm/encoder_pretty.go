package logm

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// ANSI escape codes used by the development console encoder.
const (
	colorReset       = "\x1b[0m"
	colorGray        = "\x1b[90m" // timestamp
	colorGreen       = "\x1b[32m" // INFO
	colorYellow      = "\x1b[33m" // WARN
	colorRed         = "\x1b[31m" // ERROR and above
	colorMagenta     = "\x1b[35m" // DEBUG
	colorBrightGreen = "\x1b[92m" // chevron ">"
	colorCyan        = "\x1b[36m" // caller
	colorBold        = "\x1b[1m"  // message
)

// bufferPool reuses encode buffers to avoid per-entry allocation.
var bufferPool = buffer.NewPool()

// newPrettyEncoder returns a console encoder that renders entries as
// "3:04PM INF file.go:42 > message" with ANSI colors, plus an indented
// stacktrace when one is present. It is a self-contained port of the original
// pretty-console encoder with no third-party pretty-printing dependency.
func newPrettyEncoder(cfg zapcore.EncoderConfig) zapcore.Encoder {
	return &prettyConsoleEncoder{cfg: cfg, buf: bufferPool.Get()}
}

// prettyConsoleEncoder implements zapcore.Encoder. Only the methods needed to
// render the line above carry behavior; the remaining primitive Add*/Append*
// methods are interface-satisfying no-ops because this encoder formats the
// entry message and stacktrace only, not arbitrary fields.
type prettyConsoleEncoder struct {
	cfg zapcore.EncoderConfig
	buf *buffer.Buffer
}

var _ zapcore.Encoder = (*prettyConsoleEncoder)(nil)

// Clone returns a copy with a fresh buffer, as required by zapcore.Encoder.
func (e *prettyConsoleEncoder) Clone() zapcore.Encoder {
	return &prettyConsoleEncoder{cfg: e.cfg, buf: bufferPool.Get()}
}

// EncodeEntry renders one log entry into a pooled buffer.
func (e *prettyConsoleEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	buf := bufferPool.Get()

	timestamp := colorGray + entry.Time.Format("3:04PM") + colorReset

	var levelColor string
	switch entry.Level {
	case zapcore.DebugLevel:
		levelColor = colorMagenta
	case zapcore.InfoLevel:
		levelColor = colorGreen
	case zapcore.WarnLevel:
		levelColor = colorYellow
	default: // Error, DPanic, Panic, Fatal
		levelColor = colorRed
	}
	level := levelColor + entry.Level.CapitalString()[:3] + colorReset
	caller := colorCyan + entry.Caller.TrimmedPath() + colorReset
	message := colorBold + strings.TrimSuffix(entry.Message, "\n") + colorReset

	fmt.Fprintf(buf, "%s %s %s %s>%s\t%s\n", timestamp, level, caller, colorBrightGreen, colorReset, message)

	for _, field := range fields {
		if field.Key == "stacktrace" && field.String != "" {
			for _, line := range strings.Split(strings.TrimRight(field.String, "\n"), "\n") {
				buf.AppendString("\t")
				buf.AppendString(line)
				buf.AppendByte('\n')
			}
		}
	}

	return buf, nil
}

// AddReflected renders a reflected field inline; other field types are dropped
// since the pretty encoder is for human reading, not structured capture.
func (e *prettyConsoleEncoder) AddReflected(key string, value any) error {
	e.buf.AppendString(fmt.Sprintf(" %s=%v", key, value))
	return nil
}

func (e *prettyConsoleEncoder) AddArray(string, zapcore.ArrayMarshaler) error   { return nil }
func (e *prettyConsoleEncoder) AddObject(string, zapcore.ObjectMarshaler) error { return nil }
func (e *prettyConsoleEncoder) AddBinary(string, []byte)                        {}
func (e *prettyConsoleEncoder) AddBool(string, bool)                            {}
func (e *prettyConsoleEncoder) AddByteString(string, []byte)                    {}
func (e *prettyConsoleEncoder) AddComplex128(string, complex128)                {}
func (e *prettyConsoleEncoder) AddComplex64(string, complex64)                  {}
func (e *prettyConsoleEncoder) AddDuration(string, time.Duration)               {}
func (e *prettyConsoleEncoder) AddFloat64(string, float64)                      {}
func (e *prettyConsoleEncoder) AddFloat32(string, float32)                      {}
func (e *prettyConsoleEncoder) AddInt(string, int)                              {}
func (e *prettyConsoleEncoder) AddInt64(string, int64)                          {}
func (e *prettyConsoleEncoder) AddInt32(string, int32)                          {}
func (e *prettyConsoleEncoder) AddInt16(string, int16)                          {}
func (e *prettyConsoleEncoder) AddInt8(string, int8)                            {}
func (e *prettyConsoleEncoder) AddString(string, string)                        {}
func (e *prettyConsoleEncoder) AddTime(string, time.Time)                       {}
func (e *prettyConsoleEncoder) AddUint(string, uint)                            {}
func (e *prettyConsoleEncoder) AddUint64(string, uint64)                        {}
func (e *prettyConsoleEncoder) AddUint32(string, uint32)                        {}
func (e *prettyConsoleEncoder) AddUint16(string, uint16)                        {}
func (e *prettyConsoleEncoder) AddUint8(string, uint8)                          {}
func (e *prettyConsoleEncoder) AddUintptr(string, uintptr)                      {}
func (e *prettyConsoleEncoder) OpenNamespace(string)                            {}
func (e *prettyConsoleEncoder) AppendComplex128(complex128)                     {}
func (e *prettyConsoleEncoder) AppendComplex64(complex64)                       {}
func (e *prettyConsoleEncoder) AppendFloat64(float64)                           {}
func (e *prettyConsoleEncoder) AppendFloat32(float32)                           {}
func (e *prettyConsoleEncoder) AppendInt(int)                                   {}
func (e *prettyConsoleEncoder) AppendInt64(int64)                               {}
func (e *prettyConsoleEncoder) AppendInt32(int32)                               {}
func (e *prettyConsoleEncoder) AppendInt16(int16)                               {}
func (e *prettyConsoleEncoder) AppendInt8(int8)                                 {}
func (e *prettyConsoleEncoder) AppendString(string)                             {}
func (e *prettyConsoleEncoder) AppendBool(bool)                                 {}
func (e *prettyConsoleEncoder) AppendByteString([]byte)                         {}
func (e *prettyConsoleEncoder) AppendDuration(time.Duration)                    {}
func (e *prettyConsoleEncoder) AppendTime(time.Time)                            {}
func (e *prettyConsoleEncoder) AppendUint(uint)                                 {}
func (e *prettyConsoleEncoder) AppendUint64(uint64)                             {}
func (e *prettyConsoleEncoder) AppendUint32(uint32)                             {}
func (e *prettyConsoleEncoder) AppendUint16(uint16)                             {}
func (e *prettyConsoleEncoder) AppendUint8(uint8)                               {}
func (e *prettyConsoleEncoder) AppendUintptr(uintptr)                           {}
func (e *prettyConsoleEncoder) AppendArray(zapcore.ArrayMarshaler) error        { return nil }
func (e *prettyConsoleEncoder) AppendObject(zapcore.ObjectMarshaler) error      { return nil }
func (e *prettyConsoleEncoder) AppendReflected(any) error                       { return nil }
