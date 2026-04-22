// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package patchschedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/cto-externe/lmdm/internal/db"
)

// ErrNotFound is returned when a schedule does not exist or is in another tenant.
var ErrNotFound = errors.New("patch schedule not found")

// Repository backs the patch_schedules table.
type Repository struct {
	pool *db.Pool
}

// NewRepository returns a repository bound to pool.
func NewRepository(pool *db.Pool) *Repository { return &Repository{pool: pool} }

// Create inserts a new schedule with next_fire_at pre-computed by the caller.
// Enabled defaults to true.
func (r *Repository) Create(ctx context.Context, in NewSchedule, nextFire time.Time) (*Schedule, error) {
	row := r.pool.QueryRow(ctx, `
		INSERT INTO patch_schedules
		    (tenant_id, device_id, cron_expr, filter_security_only,
		     filter_include_packages, filter_exclude_packages,
		     enabled, next_fire_at, created_by_user_id)
		VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, $8)
		RETURNING id, tenant_id, device_id, cron_expr, filter_security_only,
		          filter_include_packages, filter_exclude_packages,
		          enabled, next_fire_at, last_ran_at, last_run_status,
		          skipped_runs_count, created_by_user_id, created_at
	`,
		in.TenantID, in.DeviceID, in.CronExpr, in.FilterSecurityOnly,
		in.FilterIncludePackages, in.FilterExcludePackages,
		nextFire, in.CreatedByUserID,
	)
	return scanSchedule(row)
}

// FindDue returns the enabled schedules whose next_fire_at has passed.
// Used by the engine ticker — spans all tenants.
func (r *Repository) FindDue(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, device_id, cron_expr, filter_security_only,
		       filter_include_packages, filter_exclude_packages,
		       enabled, next_fire_at, last_ran_at, last_run_status,
		       skipped_runs_count, created_by_user_id, created_at
		FROM patch_schedules
		WHERE enabled AND next_fire_at <= $1
		ORDER BY next_fire_at ASC
	`, now)
	if err != nil {
		return nil, fmt.Errorf("FindDue: %w", err)
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// MarkRan updates last_ran_at, last_run_status and next_fire_at after a run.
func (r *Repository) MarkRan(ctx context.Context, id uuid.UUID, ranAt time.Time, status string, nextFire time.Time, skipped bool) error {
	var skipIncr int
	if skipped {
		skipIncr = 1
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE patch_schedules
		   SET last_ran_at = $2,
		       last_run_status = $3,
		       next_fire_at = $4,
		       skipped_runs_count = skipped_runs_count + $5
		 WHERE id = $1
	`, id, ranAt, status, nextFire, skipIncr)
	return err
}

// List returns schedules for the caller's tenant, most-recently-created first.
// Relies on RLS — caller must set lmdm.tenant_id GUC via middleware.
func (r *Repository) List(ctx context.Context) ([]Schedule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, device_id, cron_expr, filter_security_only,
		       filter_include_packages, filter_exclude_packages,
		       enabled, next_fire_at, last_ran_at, last_run_status,
		       skipped_runs_count, created_by_user_id, created_at
		FROM patch_schedules
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// FindByID returns a single schedule in the caller's tenant scope (via RLS).
func (r *Repository) FindByID(ctx context.Context, id uuid.UUID) (*Schedule, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, tenant_id, device_id, cron_expr, filter_security_only,
		       filter_include_packages, filter_exclude_packages,
		       enabled, next_fire_at, last_ran_at, last_run_status,
		       skipped_runs_count, created_by_user_id, created_at
		FROM patch_schedules
		WHERE id = $1
	`, id)
	s, err := scanSchedule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

// UpdateTenantPolicy writes the tenant-level reboot_policy + maintenance_window.
// maintenanceWindow may be nil (NULL in DB — falls back to "no window set").
// Does NOT validate cron syntax — callers (API handlers) must validate.
func (r *Repository) UpdateTenantPolicy(ctx context.Context, tenantID uuid.UUID, rebootPolicy string, maintenanceWindow *string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE tenants
		   SET reboot_policy = $2,
		       maintenance_window = $3
		 WHERE id = $1
	`, tenantID, rebootPolicy, maintenanceWindow)
	return err
}

// Delete removes a schedule by ID.
func (r *Repository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM patch_schedules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSchedule(r rowScanner) (*Schedule, error) {
	var s Schedule
	err := r.Scan(
		&s.ID, &s.TenantID, &s.DeviceID, &s.CronExpr, &s.FilterSecurityOnly,
		&s.FilterIncludePackages, &s.FilterExcludePackages,
		&s.Enabled, &s.NextFireAt, &s.LastRanAt, &s.LastRunStatus,
		&s.SkippedRunsCount, &s.CreatedByUserID, &s.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
