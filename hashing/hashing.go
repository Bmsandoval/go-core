// Package hashing provides fast, NON-CRYPTOGRAPHIC hashing helpers built on
// xxHash (xxhash64).
//
// These hashes are designed for speed, not security: they are fast to compute,
// trivial to reverse or forge, and unsuitable for passwords, signatures, or any
// security-sensitive comparison. Use them for cache keys, sharding, change
// detection, deduplication, and similar non-vital purposes only. For anything
// security-sensitive use crypto/sha256, golang.org/x/crypto/bcrypt, or similar.
package hashing

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/cespare/xxhash/v2"
)

// FastHash returns the xxhash64 digest of s as a uint64.
//
// It is non-cryptographic; see the package documentation.
func FastHash(s string) uint64 {
	return xxhash.Sum64String(s)
}

// FastHashHex returns the xxhash64 digest of s as a 16-character, zero-padded,
// big-endian lowercase hex string.
//
// It is non-cryptographic; see the package documentation.
func FastHashHex(s string) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], FastHash(s))
	return hex.EncodeToString(b[:])
}
