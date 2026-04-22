// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package patchschedule

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ResolvedPolicy is what the engine uses to decide what command to publish.
// MaintenanceWindow may be empty; in that case a reboot_policy of
// "next_maintenance_window" degrades silently (the agent sees the policy
// but no window is enforced client-side).
type ResolvedPolicy struct {
	RebootPolicy      string
	MaintenanceWindow string
}

// Resolver computes the effective policy for a given device by cascading
// tenant default → device override. When groups are introduced in a future
// plan, this is the single spot that gets extended (add a middle lookup on
// device_group.override between tenant and device).
type Resolver struct {
	pool *pgxpool.Pool
}

// NewResolver returns a Resolver bound to pool.
func NewResolver(pool *pgxpool.Pool) *Resolver { return &Resolver{pool: pool} }

// Resolve returns the effective reboot_policy and maintenance_window for
// the given deviceID. Intended to be called by the server-side engine which
// spans tenants, so no RLS scoping is done here — caller is responsible.
// Returns a wrapped error if the device does not exist.
func (r *Resolver) Resolve(ctx context.Context, deviceID uuid.UUID) (*ResolvedPolicy, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT
		    COALESCE(d.reboot_policy_override, t.reboot_policy),
		    COALESCE(d.maintenance_window_override, t.maintenance_window)
		FROM devices d
		JOIN tenants t ON t.id = d.tenant_id
		WHERE d.id = $1
	`, deviceID)
	var rp ResolvedPolicy
	var mw *string
	if err := row.Scan(&rp.RebootPolicy, &mw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("resolve: device %s not found", deviceID)
		}
		return nil, err
	}
	if mw != nil {
		rp.MaintenanceWindow = *mw
	}
	return &rp, nil
}
