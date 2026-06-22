// Package respond provides small helpers for writing JSON HTTP responses.
//
// Success payloads are encoded as-is. Error responses use a single,
// standardized envelope so clients can rely on a consistent shape:
//
//	{
//	  "error": {
//	    "code":    "bad_request",   // short, machine-readable slug (omitted when empty)
//	    "message": "name is required"
//	  }
//	}
//
// The "code" field is a stable, machine-friendly identifier (for example
// "not_found" or "rate_limited"), while "message" is a human-readable
// description that may change freely. When a code is not supplied explicitly,
// it defaults to a slug derived from the HTTP status text (for example status
// 400 -> "bad_request").
package respond

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

// JSON encodes v as JSON and writes it with the given HTTP status code.
//
// Encoding happens into an in-memory buffer before any header is written. This
// ensures that if encoding fails we can still emit a well-formed 500 response,
// rather than committing a status line and then silently failing mid-stream
// (the bug present in the original sources, which used `_ = enc.Encode(...)`).
//
// A nil v writes an empty body with the given status.
func JSON(w http.ResponseWriter, status int, v any) {
	if v == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		return
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		// Encoding failed and nothing has been written yet, so we can still
		// produce a clean error envelope describing the failure.
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to encode response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The body is already buffered; a write failure here means the client
	// connection is gone, and there is nothing useful to do about it.
	_, _ = w.Write(buf.Bytes())
}

// OK writes v with HTTP 200.
func OK(w http.ResponseWriter, v any) {
	JSON(w, http.StatusOK, v)
}

// Created writes v with HTTP 201.
func Created(w http.ResponseWriter, v any) {
	JSON(w, http.StatusCreated, v)
}

// Accepted writes v with HTTP 202.
func Accepted(w http.ResponseWriter, v any) {
	JSON(w, http.StatusAccepted, v)
}

// NoContent writes an empty body with HTTP 204.
func NoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// errorEnvelope is the standardized error response shape. See the package
// documentation for the wire format.
type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// Error writes an error envelope with the given status and message. The error
// code defaults to a slug derived from the status text (for example status 409
// yields "conflict").
func Error(w http.ResponseWriter, status int, message string) {
	ErrorCode(w, status, defaultCode(status), message)
}

// ErrorCode writes an error envelope with an explicit machine-readable code.
func ErrorCode(w http.ResponseWriter, status int, code, message string) {
	writeError(w, status, code, message)
}

// writeError emits the error envelope. It is the single internal path so that
// JSON's encode-failure fallback cannot recurse indefinitely.
func writeError(w http.ResponseWriter, status int, code, message string) {
	env := errorEnvelope{Error: errorBody{Code: code, Message: message}}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(env); err != nil {
		// The envelope is composed only of strings, so encoding should never
		// fail; if it somehow does, fall back to a minimal plain-text 500.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// defaultCode derives a machine-readable slug from an HTTP status code, for
// example 422 -> "unprocessable_entity". Unknown statuses yield "error".
func defaultCode(status int) string {
	text := http.StatusText(status)
	if text == "" {
		return "error"
	}
	return strings.ReplaceAll(strings.ToLower(text), " ", "_")
}

// BadRequest writes an HTTP 400 error with code "bad_request".
func BadRequest(w http.ResponseWriter, message string) {
	Error(w, http.StatusBadRequest, message)
}

// Unauthorized writes an HTTP 401 error with code "unauthorized".
func Unauthorized(w http.ResponseWriter, message string) {
	Error(w, http.StatusUnauthorized, message)
}

// Forbidden writes an HTTP 403 error with code "forbidden".
func Forbidden(w http.ResponseWriter, message string) {
	Error(w, http.StatusForbidden, message)
}

// NotFound writes an HTTP 404 error with code "not_found".
func NotFound(w http.ResponseWriter, message string) {
	Error(w, http.StatusNotFound, message)
}

// Conflict writes an HTTP 409 error with code "conflict".
func Conflict(w http.ResponseWriter, message string) {
	Error(w, http.StatusConflict, message)
}

// UnprocessableEntity writes an HTTP 422 error with code
// "unprocessable_entity". It signals a well-formed request that failed
// validation.
func UnprocessableEntity(w http.ResponseWriter, message string) {
	Error(w, http.StatusUnprocessableEntity, message)
}

// TooManyRequests writes an HTTP 429 error with code "too_many_requests".
func TooManyRequests(w http.ResponseWriter, message string) {
	Error(w, http.StatusTooManyRequests, message)
}

// InternalError writes an HTTP 500 error with code "internal_server_error".
func InternalError(w http.ResponseWriter, message string) {
	Error(w, http.StatusInternalServerError, message)
}
