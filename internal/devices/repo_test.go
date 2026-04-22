// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/db"
)

const defaultTenant = "00000000-0000-0000-0000-000000000000"

func setupRepo(t *testing.T) (*Repository, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	pg, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("lmdm"),
		postgres.WithUsername("lmdm"),
		postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancel()
	}
	return NewRepository(pool), cleanup
}

func TestIntegrationInsertAndFind(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	d := &Device{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Type:               TypeWorkstation,
		Hostname:           "PC-001",
		AgentPubkeyEd25519: []byte("ed25519-pub-bytes"),
		AgentPubkeyMLDSA:   []byte("mldsa-pub-bytes"),
	}
	if err := r.Insert(context.Background(), d); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := r.FindByID(context.Background(), tenantID, d.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Hostname != "PC-001" || got.Type != TypeWorkstation {
		t.Errorf("FindByID returned %+v", got)
	}
}

func TestIntegrationDuplicatePubKeyRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	pub := []byte("dup-ed25519-pub")
	d1 := &Device{
		ID: uuid.New(), TenantID: tenantID, Type: TypeWorkstation, Hostname: "A",
		AgentPubkeyEd25519: pub, AgentPubkeyMLDSA: []byte("ml1"),
	}
	d2 := &Device{
		ID: uuid.New(), TenantID: tenantID, Type: TypeWorkstation, Hostname: "B",
		AgentPubkeyEd25519: pub, AgentPubkeyMLDSA: []byte("ml2"),
	}
	if err := r.Insert(context.Background(), d1); err != nil {
		t.Fatal(err)
	}
	if err := r.Insert(context.Background(), d2); err == nil {
		t.Fatal("Insert with duplicate ed25519 pubkey must fail")
	}
}

func TestIntegrationRLSIsolatesDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pg, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("lmdm"),
		postgres.WithUsername("lmdm"),
		postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })

	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	tenantA := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantB := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	_, err = pool.Exec(ctx, `
		INSERT INTO tenants (id, name) VALUES
			('11111111-1111-1111-1111-111111111111', 'tenant-a'),
			('22222222-2222-2222-2222-222222222222', 'tenant-b');
		CREATE ROLE lmdm_app LOGIN PASSWORD 'appsecret';
		GRANT SELECT, INSERT, UPDATE ON devices TO lmdm_app;
		ALTER TABLE devices FORCE ROW LEVEL SECURITY;
	`)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	appPool, err := db.Open(ctx, replaceUserDevices(dsn, "lmdm_app", "appsecret"))
	if err != nil {
		t.Fatalf("open app pool: %v", err)
	}
	defer appPool.Close()

	conn, err := appPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	devID := uuid.New()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantA.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname)
		VALUES ($1, lmdm_current_tenant(), 'workstation'::device_type, 'PC-A')
	`, devID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("tenant A sees %d devices, want 1", count)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	tx2, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx2.Rollback(ctx) }()
	if _, err := tx2.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantB.String()); err != nil {
		t.Fatal(err)
	}
	if err := tx2.QueryRow(ctx, `SELECT count(*) FROM devices`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("tenant B sees %d devices, want 0 (RLS leak!)", count)
	}
}

func TestIntegrationListDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	for i := 0; i < 3; i++ {
		_ = r.Insert(context.Background(), &Device{
			ID: uuid.New(), TenantID: tenantID, Type: TypeWorkstation,
			Hostname:           fmt.Sprintf("PC-%03d", i),
			AgentPubkeyEd25519: []byte(fmt.Sprintf("ed-%d", i)),
			AgentPubkeyMLDSA:   []byte(fmt.Sprintf("ml-%d", i)),
		})
	}

	devices, total, err := r.ListDevices(context.Background(), tenantID, ListFilter{})
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if total != 3 || len(devices) != 3 {
		t.Errorf("total=%d len=%d, want 3", total, len(devices))
	}

	// Filter by hostname substring.
	_, total, err = r.ListDevices(context.Background(), tenantID, ListFilter{Hostname: "PC-001"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Errorf("filtered total = %d, want 1", total)
	}
}

func seedDeviceForHealth(t *testing.T, r *Repository, tenantID uuid.UUID, suffix string) uuid.UUID {
	t.Helper()
	d := &Device{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Type:               TypeWorkstation,
		Hostname:           "PC-HEALTH-" + suffix,
		AgentPubkeyEd25519: []byte("ed-" + suffix),
		AgentPubkeyMLDSA:   []byte("ml-" + suffix),
	}
	if err := r.Insert(context.Background(), d); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d.ID
}

func TestIntegrationUpsertHealthSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)
	deviceID := seedDeviceForHealth(t, r, tenantID, "upsert")

	batteryPct := int32(82)
	summary := HealthSummary{
		OverallScore:       1, // ORANGE
		BatteryHealthPct:   &batteryPct,
		CriticalDiskCount:  2,
		WarningDiskCount:   3,
		FwupdUpdatesCount:  4,
		FwupdCriticalCount: 1,
	}
	snapJSON := []byte(`{"deviceId":{"id":"` + deviceID.String() + `"},"overallScore":"HEALTH_SCORE_ORANGE"}`)

	if err := r.UpsertHealthSnapshot(ctx, tenantID, deviceID, summary, snapJSON); err != nil {
		t.Fatalf("UpsertHealthSnapshot: %v", err)
	}

	// Direct query to assert all snapshot columns landed.
	var (
		gotOverall   int16
		gotBattery   *int32
		gotCritical  int32
		gotWarning   int32
		gotFwupdAll  int32
		gotFwupdCrit int32
		gotSnapshot  []byte
	)
	if err := r.pool.QueryRow(ctx, `
		SELECT overall_score, battery_health_pct, critical_disk_count, warning_disk_count,
		       fwupd_updates_count, fwupd_critical_count, snapshot
		  FROM health_snapshots WHERE device_id = $1
	`, deviceID).Scan(&gotOverall, &gotBattery, &gotCritical, &gotWarning,
		&gotFwupdAll, &gotFwupdCrit, &gotSnapshot); err != nil {
		t.Fatalf("read snapshot row: %v", err)
	}
	if gotOverall != 1 {
		t.Errorf("overall_score: got %d, want 1", gotOverall)
	}
	if gotBattery == nil || *gotBattery != 82 {
		t.Errorf("battery_health_pct: got %v, want 82", gotBattery)
	}
	if gotCritical != 2 || gotWarning != 3 {
		t.Errorf("disk counts: critical=%d warning=%d, want 2/3", gotCritical, gotWarning)
	}
	if gotFwupdAll != 4 || gotFwupdCrit != 1 {
		t.Errorf("fwupd counts: total=%d critical=%d, want 4/1", gotFwupdAll, gotFwupdCrit)
	}
	var asMap map[string]any
	if err := json.Unmarshal(gotSnapshot, &asMap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if _, ok := asMap["deviceId"]; !ok {
		t.Errorf("snapshot JSON missing deviceId field")
	}

	// FindLatestHealth must return the same blob.
	blob, ts, err := r.FindLatestHealth(ctx, tenantID, deviceID)
	if err != nil {
		t.Fatalf("FindLatestHealth: %v", err)
	}
	if len(blob) == 0 {
		t.Error("FindLatestHealth returned empty blob")
	}
	if ts.IsZero() {
		t.Error("FindLatestHealth returned zero timestamp")
	}

	// Denormalized columns on devices.
	var (
		lastAt        *time.Time
		lastScore     *int16
		devBatteryPct *int32
		devFwupd      *int32
	)
	if err := r.pool.QueryRow(ctx, `
		SELECT last_health_at, last_health_score, battery_health_pct, fwupd_updates_count
		  FROM devices WHERE id = $1
	`, deviceID).Scan(&lastAt, &lastScore, &devBatteryPct, &devFwupd); err != nil {
		t.Fatalf("read devices summary: %v", err)
	}
	if lastAt == nil {
		t.Error("devices.last_health_at not set")
	}
	if lastScore == nil || *lastScore != 1 {
		t.Errorf("devices.last_health_score: got %v, want 1", lastScore)
	}
	if devBatteryPct == nil || *devBatteryPct != 82 {
		t.Errorf("devices.battery_health_pct: got %v, want 82", devBatteryPct)
	}
	if devFwupd == nil || *devFwupd != 4 {
		t.Errorf("devices.fwupd_updates_count: got %v, want 4", devFwupd)
	}
}

func TestIntegrationUpsertHealthSnapshot_TwoSnapshots_LatestWins(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)
	deviceID := seedDeviceForHealth(t, r, tenantID, "twosnap")

	first := HealthSummary{OverallScore: 0}
	firstJSON := []byte(`{"marker":"first"}`)
	if err := r.UpsertHealthSnapshot(ctx, tenantID, deviceID, first, firstJSON); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// Sleep ≥1ms to guarantee a strictly later ts.
	time.Sleep(5 * time.Millisecond)

	second := HealthSummary{OverallScore: 2}
	secondJSON := []byte(`{"marker":"second"}`)
	if err := r.UpsertHealthSnapshot(ctx, tenantID, deviceID, second, secondJSON); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	blob, _, err := r.FindLatestHealth(ctx, tenantID, deviceID)
	if err != nil {
		t.Fatalf("FindLatestHealth: %v", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(blob, &asMap); err != nil {
		t.Fatalf("latest blob not JSON: %v", err)
	}
	if asMap["marker"] != "second" {
		t.Errorf("latest snapshot marker = %v, want \"second\"", asMap["marker"])
	}

	// devices.last_health_score should reflect the latest write (2 = RED).
	var lastScore *int16
	if err := r.pool.QueryRow(ctx, `SELECT last_health_score FROM devices WHERE id = $1`, deviceID).Scan(&lastScore); err != nil {
		t.Fatal(err)
	}
	if lastScore == nil || *lastScore != 2 {
		t.Errorf("devices.last_health_score after two upserts: got %v, want 2", lastScore)
	}
}

func TestIntegrationFindLatestHealth_NoData_ReturnsSentinel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	deviceID := seedDeviceForHealth(t, r, tenantID, "nodata")

	_, _, err := r.FindLatestHealth(context.Background(), tenantID, deviceID)
	if !errors.Is(err, ErrNoHealthSnapshot) {
		t.Fatalf("FindLatestHealth on empty: got %v, want ErrNoHealthSnapshot", err)
	}
}

func TestIntegrationListTenantDeviceIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantA := uuid.MustParse(defaultTenant)
	tenantB := uuid.New()

	// Insert 2 devices for tenant A.
	for i := 0; i < 2; i++ {
		if err := r.Insert(ctx, &Device{
			ID:                 uuid.New(),
			TenantID:           tenantA,
			Type:               TypeWorkstation,
			Hostname:           fmt.Sprintf("A-%d", i),
			AgentPubkeyEd25519: []byte(fmt.Sprintf("ed-a-%d", i)),
			AgentPubkeyMLDSA:   []byte(fmt.Sprintf("ml-a-%d", i)),
		}); err != nil {
			t.Fatalf("insert tenant A device %d: %v", i, err)
		}
	}

	// Insert 1 device for tenant B (must insert tenant B row first due to FK).
	if _, err := r.pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, tenantB, "tenant-b-ltdi"); err != nil {
		t.Fatalf("insert tenant B: %v", err)
	}
	devB := uuid.New()
	if err := r.Insert(ctx, &Device{
		ID:                 devB,
		TenantID:           tenantB,
		Type:               TypeWorkstation,
		Hostname:           "B-0",
		AgentPubkeyEd25519: []byte("ed-b-0"),
		AgentPubkeyMLDSA:   []byte("ml-b-0"),
	}); err != nil {
		t.Fatalf("insert tenant B device: %v", err)
	}

	// Tenant A must return 2 IDs.
	idsA, err := r.ListTenantDeviceIDs(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListTenantDeviceIDs(tenantA): %v", err)
	}
	if len(idsA) != 2 {
		t.Errorf("tenantA: got %d IDs, want 2", len(idsA))
	}

	// Tenant B must return exactly the one device.
	idsB, err := r.ListTenantDeviceIDs(ctx, tenantB)
	if err != nil {
		t.Fatalf("ListTenantDeviceIDs(tenantB): %v", err)
	}
	if len(idsB) != 1 || idsB[0] != devB {
		t.Errorf("tenantB: got %v, want [%v]", idsB, devB)
	}

	// Unknown tenant must return empty slice, no error.
	idsNone, err := r.ListTenantDeviceIDs(ctx, uuid.New())
	if err != nil {
		t.Fatalf("ListTenantDeviceIDs(unknown): %v", err)
	}
	if len(idsNone) != 0 {
		t.Errorf("unknown tenant: got %d IDs, want 0", len(idsNone))
	}
}

func TestIntegrationUpdateRebootOverrides(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)

	// Insert a device to apply overrides to.
	deviceID := uuid.New()
	d := &Device{
		ID:                 deviceID,
		TenantID:           tenantID,
		Type:               TypeWorkstation,
		Hostname:           "reboot-override-host",
		AgentPubkeyEd25519: []byte("ed25519-pub"),
		AgentPubkeyMLDSA:   []byte("mldsa-pub"),
	}
	if err := r.Insert(ctx, d); err != nil {
		t.Fatalf("Insert device: %v", err)
	}

	// Set both overrides.
	policy := "next_maintenance_window"
	window := "0 3 * * 0"
	if err := r.UpdateRebootOverrides(ctx, tenantID, deviceID, &policy, &window); err != nil {
		t.Fatalf("UpdateRebootOverrides: %v", err)
	}

	// Reload and verify.
	var gotPolicy, gotWindow *string
	if err := r.Pool().QueryRow(ctx, `
		SELECT reboot_policy_override, maintenance_window_override
		  FROM devices WHERE id = $1 AND tenant_id = $2
	`, deviceID, tenantID).Scan(&gotPolicy, &gotWindow); err != nil {
		t.Fatalf("reload device overrides: %v", err)
	}
	if gotPolicy == nil || *gotPolicy != policy {
		t.Errorf("reboot_policy_override = %v, want %q", gotPolicy, policy)
	}
	if gotWindow == nil || *gotWindow != window {
		t.Errorf("maintenance_window_override = %v, want %q", gotWindow, window)
	}

	// Clear overrides with nil.
	if err := r.UpdateRebootOverrides(ctx, tenantID, deviceID, nil, nil); err != nil {
		t.Fatalf("UpdateRebootOverrides (clear): %v", err)
	}

	if err := r.Pool().QueryRow(ctx, `
		SELECT reboot_policy_override, maintenance_window_override
		  FROM devices WHERE id = $1 AND tenant_id = $2
	`, deviceID, tenantID).Scan(&gotPolicy, &gotWindow); err != nil {
		t.Fatalf("reload device overrides after clear: %v", err)
	}
	if gotPolicy != nil {
		t.Errorf("reboot_policy_override after clear = %v, want nil", gotPolicy)
	}
	if gotWindow != nil {
		t.Errorf("maintenance_window_override after clear = %v, want nil", gotWindow)
	}
}

func replaceUserDevices(dsn, user, password string) string {
	const scheme = "postgres://"
	if len(dsn) < len(scheme) || dsn[:len(scheme)] != scheme {
		return dsn
	}
	rest := dsn[len(scheme):]
	at := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == '@' {
			at = i
			break
		}
	}
	if at < 0 {
		return dsn
	}
	return scheme + user + ":" + password + "@" + rest[at+1:]
}
