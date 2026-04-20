// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package revocation persists and queries revoked agent-certificate serials.
// The authoritative table is revoked_certificates; the TLS handshake
// callback reads via an in-memory RevocationCache (see internal/tlspki).
package revocation

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/cto-externe/lmdm/internal/db"
)

// ErrAlreadyRevoked is returned when the serial is already present.
var ErrAlreadyRevoked = errors.New("revocation: serial already revoked")

// Repository is the tenant-scoped gateway to the revoked_certificates table.
type Repository struct {
	pool *db.Pool
}

// New wires a Repository.
func New(pool *db.Pool) *Repository { return &Repository{pool: pool} }

// Pool returns the underlying connection pool for tenant-agnostic queries.
func (r *Repository) Pool() *db.Pool { return r.pool }

// Revoke inserts a revocation row. Returns ErrAlreadyRevoked on duplicate.
func (r *Repository) Revoke(ctx context.Context, tenantID uuid.UUID, serial string, deviceID *uuid.UUID, byUserID *uuid.UUID, reason string) error {
	return r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
            INSERT INTO revoked_certificates (tenant_id, serial_number, device_id, revoked_by_user_id, reason)
            VALUES ($1, $2, $3, $4, $5)
        `, tenantID, serial, deviceID, byUserID, reason)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrAlreadyRevoked
			}
			return fmt.Errorf("revocation: insert: %w", err)
		}
		return nil
	})
}

// ListSerials returns every revoked serial in the tenant. Used by the cache
// refresh loop.
func (r *Repository) ListSerials(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	out := []string{}
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT serial_number FROM revoked_certificates WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// IsRevoked reports whether a serial is revoked for this tenant.
func (r *Repository) IsRevoked(ctx context.Context, tenantID uuid.UUID, serial string) (bool, error) {
	var exists bool
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
            SELECT EXISTS (SELECT 1 FROM revoked_certificates WHERE tenant_id = $1 AND serial_number = $2)
        `, tenantID, serial).Scan(&exists)
	})
	return exists, err
}

// --- internals ---

func (r *Repository) withTenantTx(ctx context.Context, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
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

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}
