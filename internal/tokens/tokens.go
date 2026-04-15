// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package tokens generates and validates enrollment tokens. Plaintext tokens
// are shown once to an admin and never persisted; the database stores only
// the SHA-256 hash so a DB compromise does not leak usable credentials.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
)

// PlaintextLength is the number of random bytes feeding the user-visible
// token. 32 bytes = 256 bits = base32-encoded to 52 characters without padding.
const PlaintextLength = 32

// HashSize is the length of the stored hash (SHA-256, 32 bytes).
const HashSize = 32

// Generate creates a fresh enrollment token. The plaintext is meant to be
// shown to the admin once (and copied into install commands). The hash is
// what we store in the database.
func Generate() (plaintext string, hash []byte, err error) {
	raw := make([]byte, PlaintextLength)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("tokens: rand: %w", err)
	}
	plaintext = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return plaintext, HashToken(plaintext), nil
}

// HashToken returns the SHA-256 digest of the plaintext token, used both at
// creation time (to store) and at validation time (to look up).
func HashToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}
