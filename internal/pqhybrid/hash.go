// Package pqhybrid implements hybrid post-quantum cryptographic primitives
// used by LMDM: signatures (Ed25519 + ML-DSA-65), key encapsulation
// (X25519 + ML-KEM-768), and BLAKE3 hashing.
//
// All code paths accessing classical or post-quantum primitives go through
// this package, so it is the only thing to audit for crypto changes.
package pqhybrid

import (
	"crypto/subtle"

	"github.com/zeebo/blake3"
)

// HashSize is the output size of BLAKE3 in bytes (256 bits).
const HashSize = 32

// Hash returns the BLAKE3-256 digest of data.
func Hash(data []byte) []byte {
	sum := blake3.Sum256(data)
	return sum[:]
}

// VerifyHash reports whether digest matches Hash(data) in constant time.
func VerifyHash(data, digest []byte) bool {
	if len(digest) != HashSize {
		return false
	}
	actual := Hash(data)
	return subtle.ConstantTimeCompare(actual, digest) == 1
}
