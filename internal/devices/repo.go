// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/cto-externe/lmdm/internal/db"
)

// ErrNotFound is returned when no device matches the lookup criteria.
var ErrNotFound = errors.New("devices: not found")

// Repository is the DB-backed device store.
type Repository struct {
	pool *db.Pool
}

// NewRepository wires a Repository to a connection pool.
func NewRepository(pool *db.Pool) *Repository { return &Repository{pool: pool} }

// Insert persists a new device. The caller is responsible for setting all
// required fields (id, tenant_id, type, hostname). agent_pubkey_ed25519 must
// be unique across all devices.
func (r *Repository) Insert(ctx context.Context, d *Device) error {
	const q = `
		INSERT INTO devices
		    (id, tenant_id, device_type, hostname, serial_number, manufacturer, model,
		     site_id, status, enrolled_via_token,
		     agent_pubkey_ed25519, agent_pubkey_mldsa, cert_serial)
		VALUES ($1, $2, $3::device_type, $4, $5, $6, $7, $8, COALESCE($9, 'offline')::device_status, $10, $11, $12, $13)
	`
	return r.withTenant(ctx, d.TenantID, func(tx pgx.Tx) error {
		status := string(d.Status)
		if status == "" {
			status = string(StatusOffline)
		}
		_, err := tx.Exec(ctx, q,
			d.ID, d.TenantID, string(d.Type), d.Hostname,
			d.SerialNumber, d.Manufacturer, d.Model,
			d.SiteID, status, d.EnrolledViaToken,
			d.AgentPubkeyEd25519, d.AgentPubkeyMLDSA, d.CertSerial,
		)
		if err != nil {
			return fmt.Errorf("devices: insert: %w", err)
		}
		return nil
	})
}

// FindByID returns a device by id. Returns ErrNotFound if absent.
func (r *Repository) FindByID(ctx context.Context, tenantID, id uuid.UUID) (*Device, error) {
	var d Device
	const q = `
		SELECT id, tenant_id, device_type, hostname, serial_number, manufacturer, model,
		       site_id, status, last_seen, enrolled_at, enrolled_via_token,
		       agent_pubkey_ed25519, agent_pubkey_mldsa, cert_serial, agent_version
		  FROM devices WHERE id = $1
	`
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		var devType, devStatus string
		err := tx.QueryRow(ctx, q, id).Scan(
			&d.ID, &d.TenantID, &devType, &d.Hostname,
			&d.SerialNumber, &d.Manufacturer, &d.Model,
			&d.SiteID, &devStatus, &d.LastSeen, &d.EnrolledAt, &d.EnrolledViaToken,
			&d.AgentPubkeyEd25519, &d.AgentPubkeyMLDSA, &d.CertSerial, &d.AgentVersion,
		)
		d.Type = Type(devType)
		d.Status = Status(devStatus)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("devices: find: %w", err)
	}
	return &d, nil
}

// Pool returns the underlying connection pool for callers that need to run
// tenant-agnostic queries (e.g., the heartbeat ingester which doesn't know
// the tenant up front). Use sparingly.
func (r *Repository) Pool() *db.Pool { return r.pool }

func (r *Repository) withTenant(ctx context.Context, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	return r.withTenantTx(ctx, tenantID, fn)
}

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

// ListDevices returns devices matching the filter, with total count.
func (r *Repository) ListDevices(ctx context.Context, tenantID uuid.UUID, f ListFilter) ([]Device, int, error) {
	var args []any
	argIdx := 1
	where := ""

	if f.Status != "" {
		where += fmt.Sprintf(" AND status = $%d::device_status", argIdx)
		args = append(args, f.Status)
		argIdx++
	}
	if f.Type != "" {
		where += fmt.Sprintf(" AND device_type = $%d::device_type", argIdx)
		args = append(args, f.Type)
		argIdx++
	}
	if f.Hostname != "" {
		where += fmt.Sprintf(" AND hostname ILIKE '%%' || $%d || '%%'", argIdx)
		args = append(args, f.Hostname)
	}

	var total int
	var out []Device

	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		countQ := "SELECT count(*) FROM devices WHERE 1=1" + where
		if err := tx.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
			return err
		}
		q := `SELECT id, tenant_id, device_type, hostname, serial_number, manufacturer, model,
		             site_id, status, last_seen, enrolled_at, enrolled_via_token,
		             agent_pubkey_ed25519, agent_pubkey_mldsa, cert_serial, agent_version
		        FROM devices WHERE 1=1` + where + ` ORDER BY enrolled_at DESC LIMIT 100`
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Device
			var devType, devStatus string
			if err := rows.Scan(
				&d.ID, &d.TenantID, &devType, &d.Hostname,
				&d.SerialNumber, &d.Manufacturer, &d.Model,
				&d.SiteID, &devStatus, &d.LastSeen, &d.EnrolledAt, &d.EnrolledViaToken,
				&d.AgentPubkeyEd25519, &d.AgentPubkeyMLDSA, &d.CertSerial, &d.AgentVersion,
			); err != nil {
				return err
			}
			d.Type = Type(devType)
			d.Status = Status(devStatus)
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, fmt.Errorf("devices: list: %w", err)
	}
	return out, total, nil
}

// GetInventoryJSON returns the latest inventory report JSONB for a device.
func (r *Repository) GetInventoryJSON(ctx context.Context, tenantID, deviceID uuid.UUID) (json.RawMessage, *time.Time, error) {
	const q = `SELECT report_json, received_at FROM device_inventory WHERE device_id = $1`
	var report json.RawMessage
	var receivedAt time.Time
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, deviceID).Scan(&report, &receivedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("devices: inventory: %w", err)
	}
	return report, &receivedAt, nil
}

// ComplianceInfo is the compliance status for a device.
type ComplianceInfo struct {
	OverallStatus string
	ReportJSON    json.RawMessage
	ReceivedAt    time.Time
}

// GetComplianceStatus returns the latest compliance report for a device.
func (r *Repository) GetComplianceStatus(ctx context.Context, tenantID, deviceID uuid.UUID) (*ComplianceInfo, error) {
	const q = `SELECT overall_status, report_json, received_at FROM compliance_reports WHERE device_id = $1`
	var ci ComplianceInfo
	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, deviceID).Scan(&ci.OverallStatus, &ci.ReportJSON, &ci.ReceivedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("devices: compliance: %w", err)
	}
	return &ci, nil
}

// UpdateInfo represents one available update for a device.
type UpdateInfo struct {
	PackageName      string
	CurrentVersion   string
	AvailableVersion string
	IsSecurity       bool
	Source           string
	DetectedAt       time.Time
}

// ListUpdates returns available updates for a device.
func (r *Repository) ListUpdates(ctx context.Context, tenantID, deviceID uuid.UUID) ([]UpdateInfo, bool, error) {
	const q = `SELECT package_name, current_version, available_version, is_security, source, detected_at
	             FROM device_updates WHERE device_id = $1 ORDER BY is_security DESC, package_name`
	var updates []UpdateInfo
	var reboot bool

	err := r.withTenantTx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u UpdateInfo
			if err := rows.Scan(&u.PackageName, &u.CurrentVersion, &u.AvailableVersion, &u.IsSecurity, &u.Source, &u.DetectedAt); err != nil {
				return err
			}
			updates = append(updates, u)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// Check reboot_required on the device.
		return tx.QueryRow(ctx, `SELECT reboot_required FROM devices WHERE id = $1`, deviceID).Scan(&reboot)
	})
	if err != nil {
		return nil, false, fmt.Errorf("devices: list updates: %w", err)
	}
	return updates, reboot, nil
}
