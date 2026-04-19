// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package deployments

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/cto-externe/lmdm/internal/db"
)

// ErrNotFound is returned when no deployment (or result) matches the lookup
// criteria, or when an UPDATE affects zero rows. As with the users repo, we
// conflate "no such row" with "filtered out by RLS" on purpose: exposing the
// difference would leak cross-tenant existence.
var ErrNotFound = errors.New("deployments: not found")

// deploymentColumns lists the columns selected by every read query on
// deployments, in scan order.
const deploymentColumns = `id, tenant_id, profile_id, target_group_id, target_device_ids,
    canary_device_id, status, validation_mode, validation_timeout_s,
    failure_threshold_pct, created_by_user_id, created_at,
    canary_started_at, canary_finished_at, validated_at, completed_at,
    COALESCE(reason, '')`

// resultColumns lists the columns selected by every read query on
// deployment_results, in scan order.
const resultColumns = `id, tenant_id, deployment_id, device_id, is_canary,
    status, COALESCE(snapshot_id, ''), health_check_results,
    COALESCE(error_message, ''), applied_at, rolled_back_at`

// Repository is the DB-backed deployment store. All read/write operations
// execute inside a transaction that sets the lmdm.tenant_id GUC so that
// row-level security policies on deployments and deployment_results scope
// rows to the caller's tenant.
type Repository struct {
	pool *db.Pool
}

// New wires a Repository to a connection pool.
func New(pool *db.Pool) *Repository { return &Repository{pool: pool} }

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

// scanDeployment scans the deploymentColumns from a Row into d.
func scanDeployment(row pgx.Row, d *Deployment) error {
	return row.Scan(
		&d.ID, &d.TenantID, &d.ProfileID, &d.TargetGroupID, &d.TargetDeviceIDs,
		&d.CanaryDeviceID, &d.Status, &d.ValidationMode, &d.ValidationTimeoutSeconds,
		&d.FailureThresholdPct, &d.CreatedByUserID, &d.CreatedAt,
		&d.CanaryStartedAt, &d.CanaryFinishedAt, &d.ValidatedAt, &d.CompletedAt,
		&d.Reason,
	)
}

// scanResult scans the resultColumns from a Row into r.
func scanResult(row pgx.Row, out *Result) error {
	return row.Scan(
		&out.ID, &out.TenantID, &out.DeploymentID, &out.DeviceID, &out.IsCanary,
		&out.Status, &out.SnapshotID, &out.HealthCheckResults,
		&out.ErrorMessage, &out.AppliedAt, &out.RolledBackAt,
	)
}

// Create inserts a new deployment and returns the persisted row. The caller
// may leave Status empty; it defaults to StatusPlanned. ID and CreatedAt are
// always assigned by the database.
func (r *Repository) Create(ctx context.Context, tenantID uuid.UUID, in Deployment) (*Deployment, error) {
	status := in.Status
	if status == "" {
		status = StatusPlanned
	}
	mode := in.ValidationMode
	if mode == "" {
		mode = ModeManual
	}

	const q = `
		INSERT INTO deployments (
		    tenant_id, profile_id, target_group_id, target_device_ids,
		    canary_device_id, status, validation_mode, validation_timeout_s,
		    failure_threshold_pct, created_by_user_id, reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, ''))
		RETURNING ` + deploymentColumns

	var out Deployment
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDeployment(tx.QueryRow(ctx, q,
			tenantID, in.ProfileID, in.TargetGroupID, in.TargetDeviceIDs,
			in.CanaryDeviceID, status, mode, in.ValidationTimeoutSeconds,
			in.FailureThresholdPct, in.CreatedByUserID, in.Reason,
		), &out)
	})
	if err != nil {
		return nil, fmt.Errorf("deployments: create: %w", err)
	}
	return &out, nil
}

// FindByID returns the deployment matching id within tenant. Returns
// ErrNotFound when absent or filtered by RLS.
func (r *Repository) FindByID(ctx context.Context, tenantID, id uuid.UUID) (*Deployment, error) {
	const q = `SELECT ` + deploymentColumns + ` FROM deployments WHERE id = $1`
	var d Deployment
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return scanDeployment(tx.QueryRow(ctx, q, id), &d)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("deployments: find by id: %w", err)
	}
	return &d, nil
}

// List returns deployments for a tenant matching the given filter, ordered by
// created_at DESC.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, f ListFilter) ([]Deployment, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	const q = `SELECT ` + deploymentColumns + `
		FROM deployments
		WHERE ($1 = '' OR status = $1)
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`
	var out []Deployment
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, string(f.Status), limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Deployment
			if err := scanDeployment(rows, &d); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("deployments: list: %w", err)
	}
	return out, nil
}

// UpdateStatus transitions the deployment to newStatus and, if non-empty,
// records the provided reason. Returns ErrNotFound when no row matches.
func (r *Repository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, newStatus Status, reason string) error {
	const q = `UPDATE deployments
		SET status = $2,
		    reason = CASE WHEN $3 = '' THEN reason ELSE $3 END
		WHERE id = $1`
	return r.execOne(ctx, tenantID, "update status", q, id, string(newStatus), reason)
}

// SetCanaryStarted stamps canary_started_at = NOW().
func (r *Repository) SetCanaryStarted(ctx context.Context, tenantID, id uuid.UUID) error {
	const q = `UPDATE deployments SET canary_started_at = NOW() WHERE id = $1`
	return r.execOne(ctx, tenantID, "set canary started", q, id)
}

// SetCanaryFinished stamps canary_finished_at = NOW().
func (r *Repository) SetCanaryFinished(ctx context.Context, tenantID, id uuid.UUID) error {
	const q = `UPDATE deployments SET canary_finished_at = NOW() WHERE id = $1`
	return r.execOne(ctx, tenantID, "set canary finished", q, id)
}

// SetValidated stamps validated_at = NOW().
func (r *Repository) SetValidated(ctx context.Context, tenantID, id uuid.UUID) error {
	const q = `UPDATE deployments SET validated_at = NOW() WHERE id = $1`
	return r.execOne(ctx, tenantID, "set validated", q, id)
}

// SetCompleted stamps completed_at = NOW().
func (r *Repository) SetCompleted(ctx context.Context, tenantID, id uuid.UUID) error {
	const q = `UPDATE deployments SET completed_at = NOW() WHERE id = $1`
	return r.execOne(ctx, tenantID, "set completed", q, id)
}

// UpsertResult inserts a deployment_results row or updates it if a row for
// the (deployment_id, device_id) pair already exists. The fields updated on
// conflict are status, snapshot_id, health_check_results, error_message,
// applied_at, and rolled_back_at.
func (r *Repository) UpsertResult(ctx context.Context, tenantID, deploymentID, deviceID uuid.UUID, in Result) error {
	const q = `
		INSERT INTO deployment_results (
		    tenant_id, deployment_id, device_id, is_canary, status,
		    snapshot_id, health_check_results, error_message,
		    applied_at, rolled_back_at
		) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, NULLIF($8, ''), $9, $10)
		ON CONFLICT (deployment_id, device_id) DO UPDATE SET
		    status = EXCLUDED.status,
		    snapshot_id = EXCLUDED.snapshot_id,
		    health_check_results = EXCLUDED.health_check_results,
		    error_message = EXCLUDED.error_message,
		    applied_at = EXCLUDED.applied_at,
		    rolled_back_at = EXCLUDED.rolled_back_at`
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q,
			tenantID, deploymentID, deviceID, in.IsCanary, string(in.Status),
			in.SnapshotID, in.HealthCheckResults, in.ErrorMessage,
			in.AppliedAt, in.RolledBackAt,
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("deployments: upsert result: %w", err)
	}
	return nil
}

// ListResults returns all per-device results for a deployment, ordered by
// is_canary DESC (canary first) then device_id.
func (r *Repository) ListResults(ctx context.Context, tenantID, deploymentID uuid.UUID) ([]Result, error) {
	const q = `SELECT ` + resultColumns + `
		FROM deployment_results
		WHERE deployment_id = $1
		ORDER BY is_canary DESC, device_id`
	var out []Result
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, deploymentID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var res Result
			if err := scanResult(rows, &res); err != nil {
				return err
			}
			out = append(out, res)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("deployments: list results: %w", err)
	}
	return out, nil
}

// execOne runs an UPDATE statement within the tenant-scoped transaction and
// returns ErrNotFound when zero rows are affected. The op label is only used
// to annotate wrapped errors.
//
// Zero rows affected covers two cases the caller cannot distinguish:
//
//  1. The target row does not exist.
//  2. The target row exists in a different tenant and was filtered out by
//     the RLS policy tied to lmdm.tenant_id.
//
// Conflating them is intentional and matches the users repo contract.
func (r *Repository) execOne(ctx context.Context, tenantID uuid.UUID, op, q string, args ...any) error {
	var affected int64
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, q, args...)
		if err != nil {
			return err
		}
		affected = ct.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("deployments: %s: %w", op, err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
