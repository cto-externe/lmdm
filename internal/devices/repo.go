package devices

import (
	"context"
	"errors"
	"fmt"

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
