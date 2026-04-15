// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package tokens

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/cto-externe/lmdm/internal/db"
)

// ErrTokenInvalid is returned when a token cannot be consumed: it doesn't
// exist, is expired, is revoked, or has reached its max-uses count.
var ErrTokenInvalid = errors.New("tokens: token invalid or expired")

// Token is the persisted enrollment-token record.
type Token struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Description string
	GroupIDs    []string
	SiteID      *uuid.UUID
	MaxUses     int
	UsedCount   int
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
	CreatedBy   string
}

// CreateRequest carries the parameters needed to create a new token.
type CreateRequest struct {
	TenantID    uuid.UUID
	Description string
	GroupIDs    []string
	SiteID      *uuid.UUID
	MaxUses     int
	TTL         time.Duration
	CreatedBy   string
}

// Repository is the DB-backed token store.
type Repository struct {
	pool *db.Pool
}

// NewRepository wires a Repository to a connection pool.
func NewRepository(pool *db.Pool) *Repository { return &Repository{pool: pool} }

// Create generates a new token, persists its hash, and returns the plaintext
// (caller must show this once and not store it) along with the persisted row.
func (r *Repository) Create(ctx context.Context, req CreateRequest) (string, *Token, error) {
	if req.MaxUses <= 0 {
		return "", nil, fmt.Errorf("tokens: max_uses must be > 0")
	}
	if req.GroupIDs == nil {
		req.GroupIDs = []string{}
	}

	plaintext, hash, err := Generate()
	if err != nil {
		return "", nil, err
	}

	expiresAt := time.Now().Add(req.TTL)

	var tok Token
	tok.TenantID = req.TenantID
	tok.Description = req.Description
	tok.GroupIDs = req.GroupIDs
	tok.SiteID = req.SiteID
	tok.MaxUses = req.MaxUses
	tok.ExpiresAt = expiresAt
	tok.CreatedBy = req.CreatedBy

	const q = `
		INSERT INTO enrollment_tokens
		    (tenant_id, secret_hash, description, group_ids, site_id, max_uses, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, used_count, created_at
	`
	err = r.withTenant(ctx, req.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q,
			req.TenantID, hash, req.Description, req.GroupIDs,
			req.SiteID, req.MaxUses, expiresAt, req.CreatedBy,
		).Scan(&tok.ID, &tok.UsedCount, &tok.CreatedAt)
	})
	if err != nil {
		return "", nil, fmt.Errorf("tokens: insert: %w", err)
	}
	return plaintext, &tok, nil
}

// ValidateAndConsume looks up the token by hash, atomically increments
// used_count if the token is valid, and returns the resulting record.
// Returns ErrTokenInvalid if the token cannot be consumed.
func (r *Repository) ValidateAndConsume(ctx context.Context, plaintext string) (*Token, error) {
	hash := HashToken(plaintext)
	const q = `
		UPDATE enrollment_tokens
		   SET used_count = used_count + 1
		 WHERE secret_hash = $1
		   AND revoked_at IS NULL
		   AND expires_at > NOW()
		   AND used_count < max_uses
		RETURNING id, tenant_id, description, group_ids, site_id, max_uses, used_count,
		          expires_at, revoked_at, created_at, created_by
	`
	var tok Token
	// Enrollment runs without a tenant context (we don't know it yet); we
	// rely on the unique secret_hash to scope the row. RLS bypass is OK here
	// because the application connects as table owner at MVP.
	err := r.pool.QueryRow(ctx, q, hash).Scan(
		&tok.ID, &tok.TenantID, &tok.Description, &tok.GroupIDs, &tok.SiteID,
		&tok.MaxUses, &tok.UsedCount, &tok.ExpiresAt, &tok.RevokedAt,
		&tok.CreatedAt, &tok.CreatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("tokens: consume: %w", err)
	}
	return &tok, nil
}

// Revoke marks a token as revoked. Idempotent.
func (r *Repository) Revoke(ctx context.Context, tenantID, tokenID uuid.UUID) error {
	const q = `UPDATE enrollment_tokens SET revoked_at = NOW() WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL`
	return r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, tokenID, tenantID)
		if err != nil {
			return fmt.Errorf("tokens: revoke: %w", err)
		}
		return nil
	})
}

// withTenant runs fn inside a transaction with `SET LOCAL lmdm.tenant_id`,
// the production pattern for RLS-scoped operations.
func (r *Repository) withTenant(ctx context.Context, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
