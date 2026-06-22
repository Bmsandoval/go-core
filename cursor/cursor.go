// Package cursor implements opaque keyset (seek) pagination cursors.
//
// A cursor encodes the (created_at, id) tuple of the last item in a page so the
// next query can resume from exactly that point, giving stable ordering even as
// rows are inserted or deleted. The encoded form is the base64url representation
// of a small JSON object and should be treated as opaque by clients.
//
// Unlike the original source, Decode distinguishes "no cursor" (empty input,
// reported via a sentinel error) from malformed input (a real decode error)
// rather than silently returning zero values, and Encode does not swallow JSON
// marshaling errors.
package cursor

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrEmptyCursor is returned by Decode when the cursor string is empty, which
// typically means "start from the beginning" rather than an error condition.
// Callers can check for it with errors.Is.
var ErrEmptyCursor = errors.New("cursor: empty cursor")

// payload is the wire representation of a cursor.
type payload struct {
	T time.Time `json:"t"` // created_at timestamp (UTC)
	I string    `json:"i"` // id (e.g. a UUID string)
}

// Encode returns an opaque, base64url-encoded cursor capturing the last item's
// createdAt timestamp and id. The timestamp is normalized to UTC.
//
// It returns an error if id is empty or if the tuple cannot be marshaled.
func Encode(createdAt time.Time, id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("cursor: id must not be empty")
	}
	b, err := json.Marshal(payload{T: createdAt.UTC(), I: id})
	if err != nil {
		return "", fmt.Errorf("cursor: marshaling cursor: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Decode parses an opaque cursor produced by Encode into its (createdAt, id)
// components.
//
// If cursor is empty it returns ErrEmptyCursor so callers can treat that as
// "start from the beginning". Any other failure (bad base64 or bad JSON, or a
// missing id) is returned as a wrapped error.
func Decode(cursor string) (time.Time, string, error) {
	if cursor == "" {
		return time.Time{}, "", ErrEmptyCursor
	}
	b, err := base64.URLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("cursor: decoding base64: %w", err)
	}
	var p payload
	if err := json.Unmarshal(b, &p); err != nil {
		return time.Time{}, "", fmt.Errorf("cursor: unmarshaling cursor: %w", err)
	}
	if p.I == "" {
		return time.Time{}, "", fmt.Errorf("cursor: cursor missing id")
	}
	return p.T, p.I, nil
}
