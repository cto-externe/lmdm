// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package patchschedule

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/db"
)

const defaultTenant = "00000000-0000-0000-0000-000000000000"

// setupRepo spins up a Postgres testcontainer, applies all migrations and
// returns a Repository connected as the superuser (bypasses RLS by default).
func setupRepo(t *testing.T) (*Repository, *db.Pool, func()) {
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
	return NewRepository(pool), pool, cleanup
}

// openWithTenant returns a pgxpool whose AfterConnect hook issues
// SET lmdm.tenant_id so every acquired connection is pre-scoped to tenantID.
func openWithTenant(ctx context.Context, dsn, tenantID string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 2
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET lmdm.tenant_id = '"+tenantID+"'")
		return err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

// replaceUserForRLS swaps the userinfo component of a postgres:// DSN.
func replaceUserForRLS(dsn, user, password string) string {
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

// setupRLSRepo spins up Postgres, applies migrations, seeds two tenants,
// creates the lmdm_app non-owner role with FORCE ROW LEVEL SECURITY on
// patch_schedules, and returns two Repositories — one pre-scoped to tenantA,
// one pre-scoped to tenantB — plus a superuser owner pool for seeding.
func setupRLSRepo(t *testing.T) (repoA, repoB *Repository, ownerPool *db.Pool, tenantA, tenantB uuid.UUID, cleanup func()) {
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

	owner, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}

	tenantA = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantB = uuid.MustParse("22222222-2222-2222-2222-222222222222")

	if _, err := owner.Exec(ctx, `
		INSERT INTO tenants (id, name) VALUES
			('11111111-1111-1111-1111-111111111111', 'tenant-a'),
			('22222222-2222-2222-2222-222222222222', 'tenant-b');
		CREATE ROLE lmdm_app LOGIN PASSWORD 'appsecret';
		GRANT SELECT, INSERT, UPDATE, DELETE ON patch_schedules TO lmdm_app;
		ALTER TABLE patch_schedules FORCE ROW LEVEL SECURITY;
	`); err != nil {
		owner.Close()
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatalf("seed: %v", err)
	}

	appDSN := replaceUserForRLS(dsn, "lmdm_app", "appsecret")

	rawA, err := openWithTenant(ctx, appDSN, tenantA.String())
	if err != nil {
		owner.Close()
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatalf("open pool A: %v", err)
	}
	rawB, err := openWithTenant(ctx, appDSN, tenantB.String())
	if err != nil {
		rawA.Close()
		owner.Close()
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatalf("open pool B: %v", err)
	}

	cleanup = func() {
		rawA.Close()
		rawB.Close()
		owner.Close()
		_ = pg.Terminate(ctx)
		cancel()
	}
	return NewRepository(&db.Pool{Pool: rawA}),
		NewRepository(&db.Pool{Pool: rawB}),
		owner, tenantA, tenantB, cleanup
}

func TestIntegrationPatchScheduleCreate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, pool, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)

	deviceID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname)
		VALUES ($1, $2, 'workstation', $3)
	`, deviceID, tenantID, "host-"+deviceID.String()[:8]); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	nextFire := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	in := NewSchedule{
		TenantID:              tenantID,
		DeviceID:              &deviceID,
		CronExpr:              "0 3 * * *",
		FilterSecurityOnly:    true,
		FilterIncludePackages: []string{"kernel", "openssl"},
		FilterExcludePackages: []string{"debug-tools"},
	}

	s, err := r.Create(ctx, in, nextFire)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.ID == uuid.Nil {
		t.Error("Create returned zero ID")
	}
	if s.TenantID != tenantID {
		t.Errorf("TenantID = %s, want %s", s.TenantID, tenantID)
	}
	if s.DeviceID == nil || *s.DeviceID != deviceID {
		t.Errorf("DeviceID = %v, want %s", s.DeviceID, deviceID)
	}
	if s.CronExpr != "0 3 * * *" {
		t.Errorf("CronExpr = %q, want %q", s.CronExpr, "0 3 * * *")
	}
	if !s.FilterSecurityOnly {
		t.Error("FilterSecurityOnly = false, want true")
	}
	if len(s.FilterIncludePackages) != 2 {
		t.Errorf("FilterIncludePackages = %v, want 2 items", s.FilterIncludePackages)
	}
	if !s.Enabled {
		t.Error("Enabled = false, want true")
	}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	// FindByID round-trip (superuser pool bypasses RLS).
	got, err := r.FindByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != s.ID {
		t.Errorf("FindByID.ID = %s, want %s", got.ID, s.ID)
	}
	if got.CronExpr != s.CronExpr {
		t.Errorf("FindByID.CronExpr = %q, want %q", got.CronExpr, s.CronExpr)
	}
	if len(got.FilterIncludePackages) != 2 {
		t.Errorf("FindByID.FilterIncludePackages = %v, want 2 items", got.FilterIncludePackages)
	}
}

func TestIntegrationPatchScheduleFindDue(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, pool, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)

	now := time.Now().UTC()

	past := now.Add(-2 * time.Hour)
	current := now.Add(-time.Minute)
	future := now.Add(2 * time.Hour)

	for _, tc := range []struct {
		label    string
		nextFire time.Time
	}{
		{"past", past},
		{"current", current},
		{"future", future},
	} {
		if _, err := r.Create(ctx, NewSchedule{TenantID: tenantID, CronExpr: "0 0 * * *"}, tc.nextFire); err != nil {
			t.Fatalf("Create %s: %v", tc.label, err)
		}
	}

	// Disabled schedule that is past — must NOT appear in FindDue.
	if _, err := pool.Exec(ctx, `
		INSERT INTO patch_schedules (tenant_id, cron_expr, enabled, next_fire_at)
		VALUES ($1, '0 0 * * *', FALSE, $2)
	`, tenantID, past); err != nil {
		t.Fatalf("seed disabled: %v", err)
	}

	due, err := r.FindDue(ctx, now)
	if err != nil {
		t.Fatalf("FindDue: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("FindDue returned %d rows, want 2", len(due))
	}
	// Ordered ASC by next_fire_at: past first, then current.
	if !due[0].NextFireAt.Before(due[1].NextFireAt) {
		t.Errorf("not ordered ASC: [0]=%v [1]=%v", due[0].NextFireAt, due[1].NextFireAt)
	}
}

func TestIntegrationPatchScheduleMarkRan(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, _, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)

	s, err := r.Create(ctx, NewSchedule{TenantID: tenantID, CronExpr: "0 2 * * *"}, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	ranAt := time.Now().UTC().Truncate(time.Second)
	nextFire2 := ranAt.Add(24 * time.Hour)

	if err := r.MarkRan(ctx, s.ID, ranAt, RunStatusSkippedMissedWindow, nextFire2, true); err != nil {
		t.Fatalf("MarkRan: %v", err)
	}

	got, err := r.FindByID(ctx, s.ID)
	if err != nil {
		t.Fatalf("FindByID after MarkRan: %v", err)
	}
	if got.SkippedRunsCount != 1 {
		t.Errorf("SkippedRunsCount = %d, want 1", got.SkippedRunsCount)
	}
	if got.LastRunStatus == nil || *got.LastRunStatus != RunStatusSkippedMissedWindow {
		t.Errorf("LastRunStatus = %v, want %q", got.LastRunStatus, RunStatusSkippedMissedWindow)
	}
	if got.LastRanAt == nil {
		t.Error("LastRanAt is nil, want set")
	}
}

func TestIntegrationPatchScheduleDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, _, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)

	s, err := r.Create(ctx, NewSchedule{TenantID: tenantID, CronExpr: "0 4 * * *"}, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := r.Delete(ctx, s.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Second delete must return ErrNotFound.
	if err := r.Delete(ctx, s.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete err = %v, want ErrNotFound", err)
	}
}

func TestIntegrationPatchScheduleRLSIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()

	repoA, repoB, ownerPool, tenantA, _, cleanup := setupRLSRepo(t)
	defer cleanup()

	// Insert schedule under tenant A using the superuser pool (bypasses RLS).
	nextFire := time.Now().UTC().Add(time.Hour)
	if _, err := ownerPool.Exec(ctx, `
		INSERT INTO patch_schedules (tenant_id, cron_expr, next_fire_at)
		VALUES ($1, '0 5 * * *', $2)
	`, tenantA, nextFire); err != nil {
		t.Fatalf("seed schedule tenant A: %v", err)
	}

	// repoA (lmdm.tenant_id = tenantA) must see the row.
	listA, err := repoA.List(ctx)
	if err != nil {
		t.Fatalf("repoA.List: %v", err)
	}
	if len(listA) != 1 {
		t.Errorf("repoA.List returned %d rows, want 1", len(listA))
	}

	// repoB (lmdm.tenant_id = tenantB) must see nothing.
	listB, err := repoB.List(ctx)
	if err != nil {
		t.Fatalf("repoB.List: %v", err)
	}
	if len(listB) != 0 {
		t.Errorf("repoB.List returned %d rows, want 0 (RLS leak)", len(listB))
	}
}

func TestIntegrationUpdateTenantPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, pool, cleanup := setupRepo(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.MustParse(defaultTenant)

	window := "0 22 * * 2"
	if err := r.UpdateTenantPolicy(ctx, tenantID, "immediate_after_apply", &window); err != nil {
		t.Fatalf("UpdateTenantPolicy: %v", err)
	}

	var gotPolicy string
	var gotWindow *string
	if err := pool.QueryRow(ctx, `SELECT reboot_policy, maintenance_window FROM tenants WHERE id = $1`, tenantID).
		Scan(&gotPolicy, &gotWindow); err != nil {
		t.Fatalf("reload tenant: %v", err)
	}
	if gotPolicy != "immediate_after_apply" {
		t.Errorf("reboot_policy = %q, want %q", gotPolicy, "immediate_after_apply")
	}
	if gotWindow == nil || *gotWindow != window {
		t.Errorf("maintenance_window = %v, want %q", gotWindow, window)
	}

	// Second call with nil window clears it back to NULL.
	if err := r.UpdateTenantPolicy(ctx, tenantID, "admin_only", nil); err != nil {
		t.Fatalf("UpdateTenantPolicy (clear): %v", err)
	}

	if err := pool.QueryRow(ctx, `SELECT reboot_policy, maintenance_window FROM tenants WHERE id = $1`, tenantID).
		Scan(&gotPolicy, &gotWindow); err != nil {
		t.Fatalf("reload tenant after clear: %v", err)
	}
	if gotPolicy != "admin_only" {
		t.Errorf("reboot_policy after clear = %q, want %q", gotPolicy, "admin_only")
	}
	if gotWindow != nil {
		t.Errorf("maintenance_window after clear = %v, want nil", gotWindow)
	}
}
