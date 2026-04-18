// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestIssueAndVerifyAccess_RoundTrip(t *testing.T) {
	pk := newTestKey(t)
	signer := NewJWTSigner(pk, 15*time.Minute)
	uid, tid := uuid.New(), uuid.New()
	tok, err := signer.IssueAccess(uid, tid, "admin", "user@example.org")
	if err != nil {
		t.Fatal(err)
	}
	p, err := signer.VerifyAccess(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.UserID != uid || p.TenantID != tid || p.Role != "admin" {
		t.Fatalf("mismatch: %+v", p)
	}
}

func TestVerifyAccess_RejectsExpired(t *testing.T) {
	pk := newTestKey(t)
	signer := NewJWTSigner(pk, -1*time.Second) // already expired
	tok, _ := signer.IssueAccess(uuid.New(), uuid.New(), "viewer", "x@y")
	_, err := signer.VerifyAccess(tok)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyAccess_RejectsWrongSigner(t *testing.T) {
	pk1, pk2 := newTestKey(t), newTestKey(t)
	s1 := NewJWTSigner(pk1, time.Minute)
	s2 := NewJWTSigner(pk2, time.Minute)
	tok, _ := s1.IssueAccess(uuid.New(), uuid.New(), "admin", "a@b")
	_, err := s2.VerifyAccess(tok)
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("expected ErrTokenSignatureInvalid, got %v", err)
	}
}

func TestVerifyAccess_RejectsGarbageToken(t *testing.T) {
	pk := newTestKey(t)
	s := NewJWTSigner(pk, time.Minute)
	if _, err := s.VerifyAccess("not.a.jwt"); err == nil {
		t.Error("garbage must not verify")
	}
}

func TestVerifyAccess_RejectsWrongIssuer(t *testing.T) {
	pk := newTestKey(t)
	// Sign a token with issuer other than "lmdm" directly using the library,
	// then call VerifyAccess; it must reject due to jwt.ErrTokenInvalidIssuer.
	now := time.Now().UTC()
	claims := accessClaims{
		TenantID: uuid.New().String(),
		Role:     "admin",
		Email:    "x@example.invalid",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			Issuer:    "not-lmdm",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	raw, _ := tok.SignedString(pk)
	s := NewJWTSigner(pk, time.Minute)
	if _, err := s.VerifyAccess(raw); !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		t.Fatalf("expected ErrTokenInvalidIssuer, got %v", err)
	}
}

func TestStepUp_RoundTrip(t *testing.T) {
	pk := newTestKey(t)
	s := NewJWTSigner(pk, 15*time.Minute)
	uid, tid := uuid.New(), uuid.New()
	tok, err := s.IssueStepUp(uid, tid, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	gotUID, gotTID, err := s.VerifyStepUp(tok)
	if err != nil {
		t.Fatal(err)
	}
	if gotUID != uid || gotTID != tid {
		t.Fatalf("mismatch uid=%v tid=%v", gotUID, gotTID)
	}
}

func TestStepUp_RejectsExpired(t *testing.T) {
	pk := newTestKey(t)
	s := NewJWTSigner(pk, 15*time.Minute)
	tok, _ := s.IssueStepUp(uuid.New(), uuid.New(), -1*time.Second)
	if _, _, err := s.VerifyStepUp(tok); err == nil {
		t.Error("expected expired step-up to be rejected")
	}
}

func TestStepUp_DistinctFromAccessToken(t *testing.T) {
	pk := newTestKey(t)
	s := NewJWTSigner(pk, 15*time.Minute)
	// Access token has no "stepup" audience; VerifyStepUp must reject it.
	uid, tid := uuid.New(), uuid.New()
	access, _ := s.IssueAccess(uid, tid, RoleAdmin, "a@b.test")
	if _, _, err := s.VerifyStepUp(access); err == nil {
		t.Error("access token must not verify as step-up")
	}
	// Conversely, a step-up token MUST NOT verify as access.
	stepup, _ := s.IssueStepUp(uid, tid, 5*time.Minute)
	if _, err := s.VerifyAccess(stepup); err == nil {
		t.Error("step-up token must not verify as access")
	}
}
