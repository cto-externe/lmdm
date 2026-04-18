// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RefreshToken mirrors a row of refresh_tokens.
//
// token_hash is intentionally NOT a field: every read path requires the caller
// to already possess the plaintext (or its hash), and loading the column would
// only widen the attack surface if the struct were ever logged.
type RefreshToken struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	UserID        uuid.UUID
	FamilyID      uuid.UUID
	ParentID      *uuid.UUID
	IssuedAt      time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedReason *string
	UserAgent     *string
	ClientIP      *net.IP
}

// ErrRefreshTokenNotFound is returned when no row matches a given hash.
var ErrRefreshTokenNotFound = errors.New("refresh token not found")

// RefreshTokenLifetime is the TTL for all refresh tokens (spec §7.7 = 7 days).
const RefreshTokenLifetime = 7 * 24 * time.Hour

// refreshTokenColumns lists the columns selected by every read query, in scan
// order. token_hash is omitted on purpose — see the RefreshToken godoc.
// #nosec G101 — these are SQL column names, not credentials.
const refreshTokenColumns = `id, tenant_id, user_id, family_id, parent_id,
    issued_at, expires_at, revoked_at, revoked_reason, user_agent, client_ip`

// NewOpaqueToken returns (plaintext, sha256 hash). The plaintext is only
// returned here; we never store it. Callers are expected to hand the plaintext
// to the client and persist only the hash.
func NewOpaqueToken() (string, []byte, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	plain := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	return plain, sum[:], nil
}

// HashToken computes the sha256 hash of a candidate plaintext.
func HashToken(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return sum[:]
}

// scanRefreshToken scans refreshTokenColumns from a Row or Rows-derived row
// into rt. Stays in sync with refreshTokenColumns.
func scanRefreshToken(row pgx.Row, rt *RefreshToken) error {
	var ip *netip.Addr
	if err := row.Scan(
		&rt.ID, &rt.TenantID, &rt.UserID, &rt.FamilyID, &rt.ParentID,
		&rt.IssuedAt, &rt.ExpiresAt, &rt.RevokedAt, &rt.RevokedReason,
		&rt.UserAgent, &ip,
	); err != nil {
		return err
	}
	if ip != nil {
		netIP := net.IP(ip.AsSlice())
		rt.ClientIP = &netIP
	}
	return nil
}

// ipArg converts an optional net.IP pointer into the value form pgx expects
// for an INET column: a netip.Addr when set, or nil (→ SQL NULL) otherwise.
// Mirrors the pattern used in Repository.RecordLoginSuccess.
func ipArg(ip *net.IP) any {
	if ip == nil {
		return nil
	}
	if a, ok := netip.AddrFromSlice(ip.To16()); ok {
		return a.Unmap()
	}
	return nil
}

// CreateRefreshToken inserts a new refresh token.
//
// If familyID == uuid.Nil, a new family_id is generated (this starts a new
// rotation family — e.g. on initial login). parentID may be nil for the first
// member of a family; on rotation it should point at the token that was just
// exchanged so reuse detection can walk the chain.
func (r *Repository) CreateRefreshToken(
	ctx context.Context,
	tenantID, userID uuid.UUID,
	tokenHash []byte,
	familyID uuid.UUID,
	parentID *uuid.UUID,
	ua *string,
	ip *net.IP,
) (*RefreshToken, error) {
	if familyID == uuid.Nil {
		familyID = uuid.New()
	}
	const q = `
		INSERT INTO refresh_tokens (
			tenant_id, user_id, token_hash, family_id, parent_id,
			expires_at, user_agent, client_ip
		) VALUES (
			$1, $2, $3, $4, $5,
			NOW() + make_interval(secs => $6), $7, $8
		)
		RETURNING ` + refreshTokenColumns
	var rt RefreshToken
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanRefreshToken(tx.QueryRow(ctx, q,
			tenantID, userID, tokenHash, familyID, parentID,
			RefreshTokenLifetime.Seconds(), ua, ipArg(ip),
		), &rt)
	})
	if err != nil {
		return nil, fmt.Errorf("users: create refresh token: %w", err)
	}
	return &rt, nil
}

// FindRefreshByHash looks up a token by its SHA-256 hash. Returns the row
// including revoked_at and expires_at — the caller decides what to do with an
// expired or revoked token (that is domain logic for AuthService.Refresh, not
// this repository).
//
// Returns ErrRefreshTokenNotFound if no row matches the (tenant, hash) pair.
// As with every other read in this package, the "tenant" component is enforced
// both by the WHERE clause and by the RLS policy tied to lmdm.tenant_id.
func (r *Repository) FindRefreshByHash(ctx context.Context, tenantID uuid.UUID, hash []byte) (*RefreshToken, error) {
	const q = `SELECT ` + refreshTokenColumns + `
		FROM refresh_tokens
		WHERE tenant_id = $1 AND token_hash = $2`
	var rt RefreshToken
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanRefreshToken(tx.QueryRow(ctx, q, tenantID, hash), &rt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("users: find refresh by hash: %w", err)
	}
	return &rt, nil
}

// RevokeRefresh revokes one specific token (by id) with a reason string.
//
// Returns ErrNotFound when the row is not found under tenantID; per the update()
// contract this includes rows filtered out by RLS (so a cross-tenant call
// cannot tell "no such token" apart from "token belongs to another tenant").
//
// Re-revoking an already-revoked row is a no-op: the WHERE clause filters on
// revoked_at IS NULL, so the second call simply hits no rows — we return nil
// in that case (idempotent by design).
func (r *Repository) RevokeRefresh(ctx context.Context, tenantID, id uuid.UUID, reason string) error {
	const q = `UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = $3
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`
	var affected int64
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, q, tenantID, id, reason)
		if err != nil {
			return err
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("users: revoke refresh: %w", err)
	}
	if affected == 0 {
		// Either the row doesn't exist, it belongs to another tenant (filtered
		// by RLS), or it is already revoked. We need to distinguish "already
		// revoked" (idempotent success) from the other two (ErrNotFound) so
		// callers can report lookups vs. replays correctly.
		var exists bool
		err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT EXISTS(SELECT 1 FROM refresh_tokens WHERE tenant_id = $1 AND id = $2)`,
				tenantID, id,
			).Scan(&exists)
		})
		if err != nil {
			return fmt.Errorf("users: revoke refresh: %w", err)
		}
		if !exists {
			return ErrNotFound
		}
		// Row exists and is already revoked — idempotent no-op.
	}
	return nil
}

// RevokeFamily revokes every token belonging to familyID (theft response).
//
// Idempotent: returns nil when the family is empty, entirely already revoked,
// or filtered out by RLS. Callers that need to know whether the family existed
// should check before calling.
func (r *Repository) RevokeFamily(ctx context.Context, tenantID, familyID uuid.UUID, reason string) error {
	const q = `UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = $3
		WHERE tenant_id = $1 AND family_id = $2 AND revoked_at IS NULL`
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, tenantID, familyID, reason)
		return err
	})
	if err != nil {
		return fmt.Errorf("users: revoke family: %w", err)
	}
	return nil
}

// RevokeAllForUser revokes every active refresh token for userID.
//
// Idempotent: returns nil when the user has no active tokens or no tokens at
// all. Intended for admin actions like "log this user out everywhere" and for
// automated responses (password change, role downgrade, etc.).
func (r *Repository) RevokeAllForUser(ctx context.Context, tenantID, userID uuid.UUID, reason string) error {
	const q = `UPDATE refresh_tokens
		SET revoked_at = NOW(),
		    revoked_reason = $3
		WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, tenantID, userID, reason)
		return err
	})
	if err != nil {
		return fmt.Errorf("users: revoke all for user: %w", err)
	}
	return nil
}
