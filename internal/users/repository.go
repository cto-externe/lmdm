// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package users

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cto-externe/lmdm/internal/db"
)

// ErrNotFound is returned when no user matches the lookup criteria.
var ErrNotFound = errors.New("user not found")

// ErrDuplicateEmail is returned when an email is already in use within the tenant.
var ErrDuplicateEmail = errors.New("email already in use for this tenant")

// Account lockout policy (spec §8.2). These are package-level constants so
// operators and tests can reason about them without parsing SQL.
const (
	MaxLoginFailures = 5
	LockoutDuration  = 15 * time.Minute
)

// userColumns lists the columns selected by every read query, in scan order.
const userColumns = `id, tenant_id, email, password_hash, role,
    totp_secret_encrypted, totp_enrolled_at, must_change_password, active,
    failed_login_count, locked_until, last_login_at, last_login_ip,
    deactivated_at, deactivated_by_user_id, created_at, updated_at`

// Repository is the DB-backed user store. All read/write operations are
// executed inside a transaction that sets the lmdm.tenant_id GUC so that
// row-level security policies on the users table can scope rows to the
// caller's tenant.
type Repository struct {
	pool *db.Pool
}

// New wires a Repository to a connection pool.
func New(pool *db.Pool) *Repository { return &Repository{pool: pool} }

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

// scanUser scans the userColumns from a Row or Rows-derived row into u.
func scanUser(row pgx.Row, u *User) error {
	var ip *netip.Addr
	if err := row.Scan(
		&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Role,
		&u.TOTPSecretEncrypted, &u.TOTPEnrolledAt, &u.MustChangePassword, &u.Active,
		&u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt, &ip,
		&u.DeactivatedAt, &u.DeactivatedByUserID, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return err
	}
	if ip != nil {
		netIP := net.IP(ip.AsSlice())
		u.LastLoginIP = &netIP
	}
	return nil
}

// Create inserts a new user and returns the persisted row. Returns
// ErrDuplicateEmail when the (tenant_id, lower(email)) unique index rejects
// the insert.
func (r *Repository) Create(ctx context.Context, tenantID uuid.UUID, email, passwordHash, role string) (*User, error) {
	const q = `
		INSERT INTO users (tenant_id, email, password_hash, role)
		VALUES ($1, $2, $3, $4)
		RETURNING ` + userColumns
	var u User
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanUser(tx.QueryRow(ctx, q, tenantID, email, passwordHash, role), &u)
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return nil, ErrDuplicateEmail
		}
		return nil, fmt.Errorf("users: create: %w", err)
	}
	return &u, nil
}

// FindByEmail returns the user matching email (case-insensitive) within tenant.
// Returns ErrNotFound when absent.
func (r *Repository) FindByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE tenant_id = $1 AND lower(email) = lower($2)`
	var u User
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanUser(tx.QueryRow(ctx, q, tenantID, email), &u)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("users: find by email: %w", err)
	}
	return &u, nil
}

// FindByID returns the user matching id within tenant.
func (r *Repository) FindByID(ctx context.Context, tenantID, id uuid.UUID) (*User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE tenant_id = $1 AND id = $2`
	var u User
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanUser(tx.QueryRow(ctx, q, tenantID, id), &u)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("users: find by id: %w", err)
	}
	return &u, nil
}

// List returns users for a tenant matching the given filter.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, f ListFilter) ([]User, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	const q = `SELECT ` + userColumns + `
		FROM users
		WHERE tenant_id = $1
		  AND ($2 = '' OR role = $2)
		  AND ($3 = FALSE OR active = TRUE)
		ORDER BY created_at DESC
		LIMIT $4 OFFSET $5`
	var out []User
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, tenantID, f.Role, f.ActiveOnly, limit, f.Offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u User
			if err := scanUser(rows, &u); err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("users: list: %w", err)
	}
	return out, nil
}

// SetTOTP stores the encrypted TOTP secret and stamps totp_enrolled_at.
func (r *Repository) SetTOTP(ctx context.Context, tenantID, id uuid.UUID, encrypted []byte) error {
	const q = `UPDATE users
		SET totp_secret_encrypted = $3,
		    totp_enrolled_at = NOW(),
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`
	return r.update(ctx, tenantID, "set totp", q, tenantID, id, encrypted)
}

// SetPasswordHash updates the password hash and the must-change flag.
func (r *Repository) SetPasswordHash(ctx context.Context, tenantID, id uuid.UUID, newHash string, mustChange bool) error {
	const q = `UPDATE users
		SET password_hash = $3,
		    must_change_password = $4,
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`
	return r.update(ctx, tenantID, "set password", q, tenantID, id, newHash, mustChange)
}

// SetPasswordAndRevokeAll atomically updates the password hash AND revokes every
// active refresh token for userID in a single PostgreSQL transaction. Returns
// ErrNotFound if the user row is not visible under tenantID's RLS (the revoke
// is not attempted in that case).
func (r *Repository) SetPasswordAndRevokeAll(ctx context.Context, tenantID, userID uuid.UUID, newHash string, mustChange bool, revokeReason string) error {
	return r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
            UPDATE users
            SET password_hash = $1, must_change_password = $2, updated_at = NOW()
            WHERE id = $3 AND tenant_id = $4
        `, newHash, mustChange, userID, tenantID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `
            UPDATE refresh_tokens
            SET revoked_at = NOW(), revoked_reason = $1
            WHERE user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
        `, revokeReason, userID, tenantID)
		return err
	})
}

// RecordLoginSuccess clears the failure counter / lock and stamps last_login_*.
func (r *Repository) RecordLoginSuccess(ctx context.Context, tenantID, id uuid.UUID, ip net.IP) error {
	const q = `UPDATE users
		SET failed_login_count = 0,
		    locked_until = NULL,
		    last_login_at = NOW(),
		    last_login_ip = $3,
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`
	var ipArg any
	if ip != nil {
		if a, ok := netip.AddrFromSlice(ip.To16()); ok {
			ipArg = a.Unmap()
		}
	}
	return r.update(ctx, tenantID, "record login success", q, tenantID, id, ipArg)
}

// RecordLoginFailure increments the failure counter, sets locked_until when
// the count crosses MaxLoginFailures, and returns the new (count, lockedUntil)
// pair. The threshold and lock window are defined by the package-level
// MaxLoginFailures and LockoutDuration constants.
func (r *Repository) RecordLoginFailure(ctx context.Context, tenantID, id uuid.UUID) (int, *time.Time, error) {
	const q = `UPDATE users
		SET failed_login_count = failed_login_count + 1,
		    locked_until = CASE
		        WHEN failed_login_count + 1 >= $3
		        THEN NOW() + make_interval(secs => $4)
		        ELSE locked_until
		    END,
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
		RETURNING failed_login_count, locked_until`
	var count int
	var lockedUntil *time.Time
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, tenantID, id, MaxLoginFailures, LockoutDuration.Seconds()).Scan(&count, &lockedUntil)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, ErrNotFound
	}
	if err != nil {
		return 0, nil, fmt.Errorf("users: record login failure: %w", err)
	}
	return count, lockedUntil, nil
}

// SetRole updates the role of a user.
func (r *Repository) SetRole(ctx context.Context, tenantID, id uuid.UUID, role string) error {
	const q = `UPDATE users
		SET role = $3,
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`
	return r.update(ctx, tenantID, "set role", q, tenantID, id, role)
}

// Deactivate flips active=false and records who did it / when.
func (r *Repository) Deactivate(ctx context.Context, tenantID, id, byUserID uuid.UUID) error {
	const q = `UPDATE users
		SET active = FALSE,
		    deactivated_at = NOW(),
		    deactivated_by_user_id = $3,
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`
	return r.update(ctx, tenantID, "deactivate", q, tenantID, id, byUserID)
}

// Reactivate clears the deactivation columns.
func (r *Repository) Reactivate(ctx context.Context, tenantID, id uuid.UUID) error {
	const q = `UPDATE users
		SET active = TRUE,
		    deactivated_at = NULL,
		    deactivated_by_user_id = NULL,
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`
	return r.update(ctx, tenantID, "reactivate", q, tenantID, id)
}

// Unlock clears the failure counter and lock window.
func (r *Repository) Unlock(ctx context.Context, tenantID, id uuid.UUID) error {
	const q = `UPDATE users
		SET failed_login_count = 0,
		    locked_until = NULL,
		    updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2`
	return r.update(ctx, tenantID, "unlock", q, tenantID, id)
}

// update runs an UPDATE statement within the tenant-scoped transaction and
// returns ErrNotFound when the statement affected zero rows. The op label is
// only used to annotate wrapped errors.
//
// ZERO rows affected includes two cases that the caller cannot (and should
// not) distinguish:
//
//  1. The target row does not exist.
//  2. The target row exists in a different tenant and was filtered out
//     by the RLS policy tied to lmdm.tenant_id.
//
// Conflating them is intentional: exposing the difference would let a tenant A
// principal enumerate user IDs that exist in tenant B (existence oracle).
// Keep this contract if you ever refactor.
func (r *Repository) update(ctx context.Context, tenantID uuid.UUID, op, q string, args ...any) error {
	var affected int64
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, q, args...)
		if err != nil {
			return err
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("users: %s: %w", op, err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
