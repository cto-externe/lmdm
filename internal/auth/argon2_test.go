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

func TestVerifyPassword_RejectsOutOfRangeParams(t *testing.T) {
	// Placeholder salt and hash blocks (valid base64, non-zero length) — the
	// param clamp should reject these before any argon2 compute happens, so the
	// actual bytes are irrelevant.
	const salt = "c2FsdHNhbHRzYWx0c2FsdA"
	const h = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
	cases := []struct {
		name string
		enc  string
	}{
		{"memory too high", "$argon2id$v=19$m=9999999,t=2,p=1$" + salt + "$" + h},
		{"iterations zero", "$argon2id$v=19$m=65536,t=0,p=1$" + salt + "$" + h},
		{"parallelism zero", "$argon2id$v=19$m=65536,t=2,p=0$" + salt + "$" + h},
		{"parallelism too high", "$argon2id$v=19$m=65536,t=2,p=99$" + salt + "$" + h},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if VerifyPassword("anything", c.enc) {
				t.Errorf("out-of-range params (%s) must not verify: %q", c.name, c.enc)
			}
		})
	}
}
