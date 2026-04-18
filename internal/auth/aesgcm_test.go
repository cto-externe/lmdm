// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plain := []byte("secret-totp-seed")
	ct, err := Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, out) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestDecrypt_RejectsTamper(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	ct, _ := Encrypt(key, []byte("hello"))
	ct[len(ct)-1] ^= 0x01
	if _, err := Decrypt(key, ct); err == nil {
		t.Error("tampered ciphertext should not decrypt")
	}
}

func TestEncrypt_RejectsWrongKeyLen(t *testing.T) {
	if _, err := Encrypt(make([]byte, 16), []byte("x")); err == nil {
		t.Error("expected error on non-32-byte key")
	}
}
