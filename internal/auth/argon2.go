// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package auth provides authentication primitives and services.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// OWASP 2026 recommended params for argon2id.
const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// HashPassword hashes the password with argon2id and returns the PHC-encoded
// string ($argon2id$v=19$m=...$salt$hash).
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(hash)), nil
}

// VerifyPassword returns true iff the candidate matches the encoded argon2id hash.
func VerifyPassword(candidate, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var mem, tIter uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &tIter, &par); err != nil {
		return false
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false
	}
	// Bound-check before narrowing len(want) (int) to uint32 for argon2.IDKey.
	wantLen := len(want)
	if wantLen == 0 || wantLen > int(^uint32(0)) {
		return false
	}
	got := argon2.IDKey([]byte(candidate), salt, tIter, mem, par, uint32(wantLen)) //nolint:gosec // length bounded above
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ErrInvalidHash is returned when decoding an argon2 encoded string fails.
var ErrInvalidHash = errors.New("invalid argon2 encoded hash")
