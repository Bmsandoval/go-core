// Package ids generates sortable, URL-safe identifiers.
//
// It offers two families of IDs:
//
//   - ULIDs: 26-character Crockford base32 strings composed of a 48-bit
//     millisecond timestamp followed by 80 bits of cryptographic randomness.
//     Because the timestamp occupies the most-significant bits and the encoding
//     preserves byte order, ULIDs are lexicographically sortable by creation
//     time. The Crockford base32 alphabet ("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
//     omits the ambiguous letters I, L, O and U.
//
//   - Prefixed IDs: human-scannable identifiers of the form "<prefix>_<hex>",
//     where the suffix is hex-encoded cryptographic randomness (e.g.
//     "usr_9f8c1a2b..."). These are NOT time-sortable.
//
// All randomness comes from crypto/rand. Unlike the original sources, the
// fallible read of the random source is never ignored: it is surfaced to the
// caller, and the Must* helpers panic instead of silently producing a
// low-entropy ID.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// crockford is the Crockford base32 alphabet (excludes I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a 26-character Crockford base32 ULID built from a 48-bit
// millisecond timestamp and 80 bits of cryptographic randomness. The returned
// value is lexicographically sortable by creation time.
//
// It returns an error only if the system's cryptographic random source fails.
func NewULID() (string, error) {
	ms := uint64(time.Now().UTC().UnixMilli())

	var b [16]byte
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("ids: reading random bytes for ULID: %w", err)
	}

	var out [26]byte
	// The first two characters encode the high 8 timestamp bits as 5 + 3 bits.
	out[0] = crockford[(b[0]&0xE0)>>5]
	out[1] = crockford[b[0]&0x1F]

	idx := 2
	bits := uint(0)
	var acc uint
	for i := 1; i < 16; i++ {
		acc = (acc << 8) | uint(b[i])
		bits += 8
		for bits >= 5 {
			bits -= 5
			out[idx] = crockford[(acc>>bits)&0x1F]
			idx++
		}
	}
	if bits > 0 && idx < 26 {
		out[idx] = crockford[(acc<<(5-bits))&0x1F]
		idx++
	}
	for idx < 26 {
		out[idx] = crockford[0]
		idx++
	}
	return string(out[:]), nil
}

// MustULID is like NewULID but panics if the random source fails. Use it only
// during initialization or in contexts where a failure is unrecoverable.
func MustULID() string {
	id, err := NewULID()
	if err != nil {
		panic(err)
	}
	return id
}

// Prefixed returns an identifier of the form "<prefix>_<hex>", where the suffix
// is 12 bytes (24 hex characters) of cryptographic randomness. Prefixed IDs are
// not time-sortable.
//
// It returns an error if prefix is empty or if the cryptographic random source
// fails.
func Prefixed(prefix string) (string, error) {
	if strings.TrimSpace(prefix) == "" {
		return "", fmt.Errorf("ids: prefix must not be empty")
	}
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("ids: reading random bytes for prefixed id: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(b[:]), nil
}

// MustPrefixed is like Prefixed but panics on error. Use it only when a failure
// is unrecoverable.
func MustPrefixed(prefix string) string {
	id, err := Prefixed(prefix)
	if err != nil {
		panic(err)
	}
	return id
}
