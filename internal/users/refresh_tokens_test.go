// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package users

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIntegration_CreateAndFindRefreshByHash(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	u, err := r.Create(ctx, tenantID, "rt-create@x.test", "hash", "operator")
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	plain, hash, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	if plain == "" {
		t.Fatal("NewOpaqueToken returned empty plaintext")
	}
	if !bytes.Equal(hash, HashToken(plain)) {
		t.Fatal("HashToken(plain) != hash returned by NewOpaqueToken")
	}

	ua := "Mozilla/5.0 (TestAgent)"
	rt, err := r.CreateRefreshToken(ctx, tenantID, u.ID, hash, uuid.Nil, nil, &ua, nil)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	if rt.FamilyID == uuid.Nil {
		t.Error("CreateRefreshToken did not assign a FamilyID when passed uuid.Nil")
	}
	if rt.ParentID != nil {
		t.Errorf("ParentID = %v, want nil for first token in a family", rt.ParentID)
	}
	if rt.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil on freshly created token", rt.RevokedAt)
	}
	if !rt.ExpiresAt.After(time.Now()) {
		t.Errorf("ExpiresAt = %v, want future", rt.ExpiresAt)
	}
	if rt.UserAgent == nil || *rt.UserAgent != ua {
		t.Errorf("UserAgent = %v, want %q", rt.UserAgent, ua)
	}

	// FindRefreshByHash with the hash of the same plaintext must return the row.
	got, err := r.FindRefreshByHash(ctx, tenantID, HashToken(plain))
	if err != nil {
		t.Fatalf("FindRefreshByHash: %v", err)
	}
	if got.ID != rt.ID {
		t.Errorf("FindRefreshByHash id = %s, want %s", got.ID, rt.ID)
	}
	if got.FamilyID != rt.FamilyID {
		t.Errorf("FindRefreshByHash FamilyID = %s, want %s", got.FamilyID, rt.FamilyID)
	}
}

func TestIntegration_RevokeFamily_RevokesAllMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	u, err := r.Create(ctx, tenantID, "rt-family@x.test", "hash", "operator")
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	plain1, hash1, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken #1: %v", err)
	}
	rt1, err := r.CreateRefreshToken(ctx, tenantID, u.ID, hash1, uuid.Nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRefreshToken #1: %v", err)
	}
	_ = plain1

	// Second token chains from the first — same family, parent_id = rt1.ID.
	_, hash2, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken #2: %v", err)
	}
	rt2, err := r.CreateRefreshToken(ctx, tenantID, u.ID, hash2, rt1.FamilyID, &rt1.ID, nil, nil)
	if err != nil {
		t.Fatalf("CreateRefreshToken #2: %v", err)
	}
	if rt2.FamilyID != rt1.FamilyID {
		t.Fatalf("second token FamilyID = %s, want %s (same family)", rt2.FamilyID, rt1.FamilyID)
	}
	if rt2.ParentID == nil || *rt2.ParentID != rt1.ID {
		t.Fatalf("second token ParentID = %v, want %s", rt2.ParentID, rt1.ID)
	}

	// Revoke the whole family.
	if err := r.RevokeFamily(ctx, tenantID, rt1.FamilyID, "reuse_detected"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	// Both rows must show revoked_at != nil and revoked_reason = "reuse_detected".
	for i, h := range [][]byte{hash1, hash2} {
		got, err := r.FindRefreshByHash(ctx, tenantID, h)
		if err != nil {
			t.Fatalf("FindRefreshByHash after revoke (#%d): %v", i+1, err)
		}
		if got.RevokedAt == nil {
			t.Errorf("token #%d: RevokedAt is nil after RevokeFamily", i+1)
		}
		if got.RevokedReason == nil || *got.RevokedReason != "reuse_detected" {
			t.Errorf("token #%d: RevokedReason = %v, want %q", i+1, got.RevokedReason, "reuse_detected")
		}
	}

	// RevokeFamily again is a no-op (idempotent).
	if err := r.RevokeFamily(ctx, tenantID, rt1.FamilyID, "reuse_detected"); err != nil {
		t.Errorf("RevokeFamily (second call) must be idempotent, got %v", err)
	}
}

func TestIntegration_FindRefreshByHash_NotFound_WhenAbsent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	bogus := HashToken("definitely-not-a-real-token")
	_, err := r.FindRefreshByHash(ctx, tenantID, bogus)
	if !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Fatalf("FindRefreshByHash bogus err = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestIntegration_RevokeAllForUser_RevokesActiveOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	u, err := r.Create(ctx, tenantID, "rt-alluser@x.test", "hash", "operator")
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	// Token A: will be manually revoked before RevokeAllForUser.
	_, hashA, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken A: %v", err)
	}
	rtA, err := r.CreateRefreshToken(ctx, tenantID, u.ID, hashA, uuid.Nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRefreshToken A: %v", err)
	}
	if err := r.RevokeRefresh(ctx, tenantID, rtA.ID, "logout"); err != nil {
		t.Fatalf("RevokeRefresh A: %v", err)
	}
	gotA, err := r.FindRefreshByHash(ctx, tenantID, hashA)
	if err != nil {
		t.Fatalf("FindRefreshByHash A: %v", err)
	}
	if gotA.RevokedAt == nil {
		t.Fatal("precondition: rtA must be revoked before RevokeAllForUser")
	}
	revokedAtBefore := *gotA.RevokedAt
	revokedReasonBefore := *gotA.RevokedReason

	// Token B: still active.
	_, hashB, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken B: %v", err)
	}
	rtB, err := r.CreateRefreshToken(ctx, tenantID, u.ID, hashB, uuid.Nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRefreshToken B: %v", err)
	}

	// Revoke all for user.
	if err := r.RevokeAllForUser(ctx, tenantID, u.ID, "password_changed"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}

	// B must now be revoked with the new reason.
	gotB, err := r.FindRefreshByHash(ctx, tenantID, hashB)
	if err != nil {
		t.Fatalf("FindRefreshByHash B: %v", err)
	}
	if gotB.RevokedAt == nil {
		t.Fatal("token B: RevokedAt is nil after RevokeAllForUser")
	}
	if gotB.RevokedReason == nil || *gotB.RevokedReason != "password_changed" {
		t.Errorf("token B: RevokedReason = %v, want %q", gotB.RevokedReason, "password_changed")
	}
	_ = rtB

	// A's revoked_at / revoked_reason must be unchanged (already-revoked rows
	// are filtered out by the revoked_at IS NULL clause).
	gotA2, err := r.FindRefreshByHash(ctx, tenantID, hashA)
	if err != nil {
		t.Fatalf("FindRefreshByHash A (after): %v", err)
	}
	if gotA2.RevokedAt == nil || !gotA2.RevokedAt.Equal(revokedAtBefore) {
		t.Errorf("token A RevokedAt changed: before=%v after=%v", revokedAtBefore, gotA2.RevokedAt)
	}
	if gotA2.RevokedReason == nil || *gotA2.RevokedReason != revokedReasonBefore {
		t.Errorf("token A RevokedReason changed: before=%q after=%v", revokedReasonBefore, gotA2.RevokedReason)
	}

	// RevokeAllForUser on a user with no active tokens is a no-op.
	if err := r.RevokeAllForUser(ctx, tenantID, u.ID, "password_changed"); err != nil {
		t.Errorf("RevokeAllForUser (no active tokens) must be nil, got %v", err)
	}
}

func TestIntegration_RLS_IsolatesRefreshTokensAcrossTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()

	r, tenantA, tenantB, cleanup := setupRLSRepo(t)
	defer cleanup()

	// Seed: user + refresh token under tenant A.
	ua, err := r.Create(ctx, tenantA, "rt-rls@x.test", "$argon2id$dummy", "admin")
	if err != nil {
		t.Fatalf("Create user A: %v", err)
	}
	_, hash, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	rt, err := r.CreateRefreshToken(ctx, tenantA, ua.ID, hash, uuid.Nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRefreshToken A: %v", err)
	}

	// Under tenant B: FindRefreshByHash must not see the token.
	if _, err := r.FindRefreshByHash(ctx, tenantB, hash); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Fatalf("FindRefreshByHash cross-tenant err = %v, want ErrRefreshTokenNotFound", err)
	}

	// Under tenant B: RevokeRefresh on tenant A's token must return ErrNotFound
	// (rows filtered by RLS are indistinguishable from "no such row" — see the
	// update()/RevokeRefresh godoc).
	if err := r.RevokeRefresh(ctx, tenantB, rt.ID, "cross_tenant_attempt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RevokeRefresh cross-tenant err = %v, want ErrNotFound", err)
	}

	// Sanity: tenant A still sees an unrevoked token.
	gotA, err := r.FindRefreshByHash(ctx, tenantA, hash)
	if err != nil {
		t.Fatalf("tenant A must still see its own token: %v", err)
	}
	if gotA.RevokedAt != nil {
		t.Errorf("tenant A token RevokedAt = %v after cross-tenant revoke attempt, want nil", gotA.RevokedAt)
	}

	// And RevokeFamily / RevokeAllForUser from tenant B must leave the token
	// untouched (both are idempotent-nil even when RLS filters everything out).
	if err := r.RevokeFamily(ctx, tenantB, rt.FamilyID, "cross_tenant_attempt"); err != nil {
		t.Fatalf("RevokeFamily cross-tenant err = %v, want nil (idempotent)", err)
	}
	if err := r.RevokeAllForUser(ctx, tenantB, ua.ID, "cross_tenant_attempt"); err != nil {
		t.Fatalf("RevokeAllForUser cross-tenant err = %v, want nil (idempotent)", err)
	}
	gotA2, err := r.FindRefreshByHash(ctx, tenantA, hash)
	if err != nil {
		t.Fatalf("tenant A refetch: %v", err)
	}
	if gotA2.RevokedAt != nil {
		t.Errorf("tenant A token leaked a cross-tenant revocation: RevokedAt = %v", gotA2.RevokedAt)
	}
}
