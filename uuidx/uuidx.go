// Package uuidx provides conversions between UUID strings and their 16-byte
// binary representation, suitable for storing UUIDs as BINARY(16) columns.
//
// Every function validates its input and returns an error on malformed data;
// none panic. This differs from the original source, whose binary-to-string
// helpers silently returned empty strings (or truncated/zero-padded results)
// for inputs that were not exactly 16 bytes.
package uuidx

import (
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

// ParseUUIDString parses a canonical UUID string into its 16-byte binary form.
//
// An empty string yields (nil, nil) so callers can represent an absent UUID as
// SQL NULL. Any non-empty but invalid string returns an error.
func ParseUUIDString(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	parsed, err := uuid.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("uuidx: parsing UUID %q: %w", s, err)
	}
	out := make([]byte, 16)
	copy(out, parsed[:])
	return out, nil
}

// UUIDToString renders a 16-byte binary UUID as its canonical hyphenated string
// (e.g. "550e8400-e29b-41d4-a716-446655440000").
//
// It returns an error if b is not exactly 16 bytes.
func UUIDToString(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("uuidx: UUID must be 16 bytes, got %d", len(b))
	}
	var arr [16]byte
	copy(arr[:], b)
	return uuid.UUID(arr).String(), nil
}

// UUIDToHexString renders a 16-byte binary UUID as a 32-character lowercase hex
// string with no hyphens.
//
// It returns an error if b is not exactly 16 bytes.
func UUIDToHexString(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("uuidx: UUID must be 16 bytes, got %d", len(b))
	}
	return hex.EncodeToString(b), nil
}
