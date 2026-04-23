// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package patchschedule

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestIntegrationResolver_UsesTenantDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	_, pool, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)

	// Set tenant-level policy and window.
	if _, err := pool.Exec(ctx, `
		UPDATE tenants
		   SET reboot_policy     = 'immediate_after_apply',
		       maintenance_window = '0 22 * * 2'
		 WHERE id = $1
	`, tenantID); err != nil {
		t.Fatalf("seed tenant policy: %v", err)
	}

	// Create device with no overrides.
	deviceID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname)
		VALUES ($1, $2, 'workstation', $3)
	`, deviceID, tenantID, "host-"+deviceID.String()[:8]); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	res := NewResolver(pool.Pool)
	got, err := res.Resolve(ctx, deviceID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.RebootPolicy != "immediate_after_apply" {
		t.Errorf("RebootPolicy = %q, want %q", got.RebootPolicy, "immediate_after_apply")
	}
	if got.MaintenanceWindow != "0 22 * * 2" {
		t.Errorf("MaintenanceWindow = %q, want %q", got.MaintenanceWindow, "0 22 * * 2")
	}
}

func TestIntegrationResolver_DeviceOverrideWins(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	_, pool, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)
	// Tenant keeps default: admin_only, no window.

	deviceID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname,
		                     reboot_policy_override, maintenance_window_override)
		VALUES ($1, $2, 'workstation', $3, 'immediate_after_apply', '0 3 * * *')
	`, deviceID, tenantID, "host-"+deviceID.String()[:8]); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	res := NewResolver(pool.Pool)
	got, err := res.Resolve(ctx, deviceID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.RebootPolicy != "immediate_after_apply" {
		t.Errorf("RebootPolicy = %q, want %q", got.RebootPolicy, "immediate_after_apply")
	}
	if got.MaintenanceWindow != "0 3 * * *" {
		t.Errorf("MaintenanceWindow = %q, want %q", got.MaintenanceWindow, "0 3 * * *")
	}
}

func TestIntegrationResolver_PartialOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	_, pool, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)

	// Tenant: immediate_after_apply + window.
	if _, err := pool.Exec(ctx, `
		UPDATE tenants
		   SET reboot_policy     = 'immediate_after_apply',
		       maintenance_window = '0 4 * * 0'
		 WHERE id = $1
	`, tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Device: only reboot_policy_override set, no window override.
	deviceID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname,
		                     reboot_policy_override)
		VALUES ($1, $2, 'workstation', $3, 'admin_only')
	`, deviceID, tenantID, "host-"+deviceID.String()[:8]); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	res := NewResolver(pool.Pool)
	got, err := res.Resolve(ctx, deviceID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.RebootPolicy != "admin_only" {
		t.Errorf("RebootPolicy = %q, want %q", got.RebootPolicy, "admin_only")
	}
	if got.MaintenanceWindow != "0 4 * * 0" {
		t.Errorf("MaintenanceWindow = %q, want %q (should fall back to tenant)", got.MaintenanceWindow, "0 4 * * 0")
	}
}

func TestIntegrationResolver_DeviceNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	_, pool, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	res := NewResolver(pool.Pool)

	_, err := res.Resolve(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected error for unknown device, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q does not contain %q", err.Error(), "not found")
	}
}

func TestIntegrationResolver_EmptyMaintenanceWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	_, pool, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)
	// Tenant default: admin_only, no window (migration default).

	deviceID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname)
		VALUES ($1, $2, 'workstation', $3)
	`, deviceID, tenantID, "host-"+deviceID.String()[:8]); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	res := NewResolver(pool.Pool)
	got, err := res.Resolve(ctx, deviceID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.MaintenanceWindow != "" {
		t.Errorf("MaintenanceWindow = %q, want empty string", got.MaintenanceWindow)
	}
}
