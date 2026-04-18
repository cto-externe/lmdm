// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"strings"
	"testing"
)

func TestHashPassword_ProducesArgon2idEncoded(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("expected argon2id encoded, got %q", h)
	}
}

func TestVerifyPassword_AcceptsValid_RejectsInvalid(t *testing.T) {
	h, _ := HashPassword("good-pass-12")
	if !VerifyPassword("good-pass-12", h) {
		t.Error("should accept correct password")
	}
	if VerifyPassword("wrong-pass", h) {
		t.Error("should reject wrong password")
	}
}

func TestVerifyPassword_RejectsMalformedHash(t *testing.T) {
	if VerifyPassword("anything", "not-an-argon2-hash") {
		t.Error("malformed hash must not verify")
	}
}
