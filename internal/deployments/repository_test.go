// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package deployments

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/db"
)

const defaultTenant = "00000000-0000-0000-0000-000000000000"

// seedFixtures inserts one profile + one device under tenantID and returns
// their ids. Both are inserted as the connected role; when the RLS harness
// uses the non-owner role we also need SELECT/INSERT grants on profiles and
// devices so callers can seed test data through the same pool.
func seedFixtures(t *testing.T, ctx context.Context, pool *db.Pool, tenantID uuid.UUID) (profileID, deviceID uuid.UUID) {
	t.Helper()
	profileID = uuid.New()
	deviceID = uuid.New()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("seed begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("seed set_config: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO profiles (id, tenant_id, name, yaml_content, json_content)
		VALUES ($1, $2, $3, '{}', '{}'::jsonb)
	`, profileID, tenantID, "test-profile-"+profileID.String()[:8]); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname)
		VALUES ($1, $2, 'workstation', $3)
	`, deviceID, tenantID, "host-"+deviceID.String()[:8]); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	return profileID, deviceID
}

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
	return New(pool), pool, cleanup
}

// setupRLSRepo spins up Postgres, runs migrations, seeds two tenants, creates
// the non-owner lmdm_app role with FORCE ROW LEVEL SECURITY on deployments
// and deployment_results, then returns a Repository backed by a pool
// connected as lmdm_app. Also returns the lmdm_app-scoped pool so tests can
// seed per-tenant fixtures (profiles, devices) through it.
func setupRLSRepo(t *testing.T) (*Repository, *db.Pool, uuid.UUID, uuid.UUID, func()) {
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

	// Open as superuser to seed tenants + create the non-owner role.
	ownerPool, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}

	tenantA := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantB := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	if _, err := ownerPool.Exec(ctx, `
		INSERT INTO tenants (id, name) VALUES
			('11111111-1111-1111-1111-111111111111', 'tenant-a'),
			('22222222-2222-2222-2222-222222222222', 'tenant-b');
		CREATE ROLE lmdm_app LOGIN PASSWORD 'appsecret';
		GRANT SELECT, INSERT, UPDATE, DELETE ON deployments TO lmdm_app;
		GRANT SELECT, INSERT, UPDATE, DELETE ON deployment_results TO lmdm_app;
		GRANT SELECT, INSERT ON profiles TO lmdm_app;
		GRANT SELECT, INSERT ON devices TO lmdm_app;
		ALTER TABLE deployments FORCE ROW LEVEL SECURITY;
		ALTER TABLE deployment_results FORCE ROW LEVEL SECURITY;
		ALTER TABLE profiles FORCE ROW LEVEL SECURITY;
		ALTER TABLE devices FORCE ROW LEVEL SECURITY;
	`); err != nil {
		ownerPool.Close()
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatalf("seed: %v", err)
	}
	ownerPool.Close()

	appPool, err := db.Open(ctx, replaceUserForRLS(dsn, "lmdm_app", "appsecret"))
	if err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatalf("open app pool: %v", err)
	}

	cleanup := func() {
		appPool.Close()
		_ = pg.Terminate(ctx)
		cancel()
	}
	return New(appPool), appPool, tenantA, tenantB, cleanup
}

// replaceUserForRLS swaps the userinfo component of a postgres:// DSN so the
// test can reconnect as the non-owner lmdm_app role.
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

func TestIntegration_CreateAndFindByID(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, pool, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()
	profileID, deviceID := seedFixtures(t, ctx, pool, tenantID)

	in := Deployment{
		ProfileID:                profileID,
		TargetDeviceIDs:          []uuid.UUID{deviceID},
		CanaryDeviceID:           deviceID,
		ValidationMode:           ModeManual,
		ValidationTimeoutSeconds: 1800,
		FailureThresholdPct:      10,
	}

	created, err := r.Create(ctx, tenantID, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Error("Create returned zero ID")
	}
	if created.Status != StatusPlanned {
		t.Errorf("Status = %q, want %q", created.Status, StatusPlanned)
	}
	if created.ValidationMode != ModeManual {
		t.Errorf("ValidationMode = %q, want %q", created.ValidationMode, ModeManual)
	}
	if created.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	if len(created.TargetDeviceIDs) != 1 || created.TargetDeviceIDs[0] != deviceID {
		t.Errorf("TargetDeviceIDs = %v, want [%s]", created.TargetDeviceIDs, deviceID)
	}

	got, err := r.FindByID(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("FindByID returned id %s, want %s", got.ID, created.ID)
	}
	if got.CanaryDeviceID != deviceID {
		t.Errorf("CanaryDeviceID = %s, want %s", got.CanaryDeviceID, deviceID)
	}

	// Missing ID → ErrNotFound.
	if _, err := r.FindByID(ctx, tenantID, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindByID(missing) err = %v, want ErrNotFound", err)
	}
}

func TestIntegration_UpdateStatus_Transitions(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, pool, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()
	profileID, deviceID := seedFixtures(t, ctx, pool, tenantID)

	created, err := r.Create(ctx, tenantID, Deployment{
		ProfileID:                profileID,
		TargetDeviceIDs:          []uuid.UUID{deviceID},
		CanaryDeviceID:           deviceID,
		ValidationMode:           ModeAuto,
		ValidationTimeoutSeconds: 1800,
		FailureThresholdPct:      10,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Happy-path transitions: planned → canary_running → canary_ok.
	if err := r.UpdateStatus(ctx, tenantID, created.ID, StatusCanaryRunning, ""); err != nil {
		t.Fatalf("UpdateStatus canary_running: %v", err)
	}
	if err := r.SetCanaryStarted(ctx, tenantID, created.ID); err != nil {
		t.Fatalf("SetCanaryStarted: %v", err)
	}
	if err := r.UpdateStatus(ctx, tenantID, created.ID, StatusCanaryOK, ""); err != nil {
		t.Fatalf("UpdateStatus canary_ok: %v", err)
	}
	if err := r.SetCanaryFinished(ctx, tenantID, created.ID); err != nil {
		t.Fatalf("SetCanaryFinished: %v", err)
	}
	if err := r.SetValidated(ctx, tenantID, created.ID); err != nil {
		t.Fatalf("SetValidated: %v", err)
	}
	if err := r.UpdateStatus(ctx, tenantID, created.ID, StatusRollingOut, ""); err != nil {
		t.Fatalf("UpdateStatus rolling_out: %v", err)
	}
	if err := r.UpdateStatus(ctx, tenantID, created.ID, StatusCompleted, ""); err != nil {
		t.Fatalf("UpdateStatus completed: %v", err)
	}
	if err := r.SetCompleted(ctx, tenantID, created.ID); err != nil {
		t.Fatalf("SetCompleted: %v", err)
	}

	got, err := r.FindByID(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Status != StatusCompleted {
		t.Errorf("Status = %q, want %q", got.Status, StatusCompleted)
	}
	if got.CanaryStartedAt == nil {
		t.Error("CanaryStartedAt is nil, want set")
	}
	if got.CanaryFinishedAt == nil {
		t.Error("CanaryFinishedAt is nil, want set")
	}
	if got.ValidatedAt == nil {
		t.Error("ValidatedAt is nil, want set")
	}
	if got.CompletedAt == nil {
		t.Error("CompletedAt is nil, want set")
	}

	// Reason is persisted when non-empty, left alone when empty.
	if err := r.UpdateStatus(ctx, tenantID, created.ID, StatusRolledBack, "canary failed SMART check"); err != nil {
		t.Fatalf("UpdateStatus rolled_back w/reason: %v", err)
	}
	got, err = r.FindByID(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Reason != "canary failed SMART check" {
		t.Errorf("Reason = %q, want %q", got.Reason, "canary failed SMART check")
	}
	// Empty reason leaves the previous value intact.
	if err := r.UpdateStatus(ctx, tenantID, created.ID, StatusPartiallyFailed, ""); err != nil {
		t.Fatalf("UpdateStatus partially_failed: %v", err)
	}
	got, err = r.FindByID(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Reason != "canary failed SMART check" {
		t.Errorf("Reason = %q after empty-reason update, want unchanged", got.Reason)
	}

	// Missing id → ErrNotFound.
	if err := r.UpdateStatus(ctx, tenantID, uuid.New(), StatusCompleted, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateStatus(missing) err = %v, want ErrNotFound", err)
	}
}

func TestIntegration_UpsertResult_InsertThenUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, pool, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()
	profileID, deviceID := seedFixtures(t, ctx, pool, tenantID)

	dep, err := r.Create(ctx, tenantID, Deployment{
		ProfileID:                profileID,
		TargetDeviceIDs:          []uuid.UUID{deviceID},
		CanaryDeviceID:           deviceID,
		ValidationMode:           ModeManual,
		ValidationTimeoutSeconds: 1800,
		FailureThresholdPct:      10,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// First upsert: insert.
	if err := r.UpsertResult(ctx, tenantID, dep.ID, deviceID, Result{
		IsCanary:   true,
		Status:     ResultApplying,
		SnapshotID: "snap-1",
	}); err != nil {
		t.Fatalf("UpsertResult insert: %v", err)
	}
	results, err := r.ListResults(ctx, tenantID, dep.ID)
	if err != nil {
		t.Fatalf("ListResults: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ListResults len = %d, want 1", len(results))
	}
	if results[0].Status != ResultApplying {
		t.Errorf("Status = %q, want %q", results[0].Status, ResultApplying)
	}
	if results[0].SnapshotID != "snap-1" {
		t.Errorf("SnapshotID = %q, want %q", results[0].SnapshotID, "snap-1")
	}
	if !results[0].IsCanary {
		t.Error("IsCanary = false, want true")
	}

	// Second upsert on the same (deployment_id, device_id) pair: UPDATE.
	now := time.Now().UTC().Truncate(time.Second)
	if err := r.UpsertResult(ctx, tenantID, dep.ID, deviceID, Result{
		IsCanary:           true,
		Status:             ResultSuccess,
		SnapshotID:         "snap-2",
		HealthCheckResults: []byte(`{"smart":"ok","battery":100}`),
		AppliedAt:          &now,
	}); err != nil {
		t.Fatalf("UpsertResult update: %v", err)
	}
	results, err = r.ListResults(ctx, tenantID, dep.ID)
	if err != nil {
		t.Fatalf("ListResults (after update): %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("ListResults len = %d, want 1 (upsert must not double-insert)", len(results))
	}
	if results[0].Status != ResultSuccess {
		t.Errorf("Status = %q, want %q", results[0].Status, ResultSuccess)
	}
	if results[0].SnapshotID != "snap-2" {
		t.Errorf("SnapshotID = %q, want %q", results[0].SnapshotID, "snap-2")
	}
	if len(results[0].HealthCheckResults) == 0 {
		t.Error("HealthCheckResults is empty, want JSONB bytes")
	}
	if results[0].AppliedAt == nil {
		t.Error("AppliedAt is nil, want set after update")
	}

	// Error transition with rolled_back_at stamp.
	rolled := time.Now().UTC().Truncate(time.Second)
	if err := r.UpsertResult(ctx, tenantID, dep.ID, deviceID, Result{
		IsCanary:     true,
		Status:       ResultRolledBack,
		SnapshotID:   "snap-2",
		ErrorMessage: "health degraded post-apply",
		RolledBackAt: &rolled,
	}); err != nil {
		t.Fatalf("UpsertResult rolled_back: %v", err)
	}
	results, err = r.ListResults(ctx, tenantID, dep.ID)
	if err != nil {
		t.Fatalf("ListResults: %v", err)
	}
	if results[0].Status != ResultRolledBack {
		t.Errorf("Status = %q, want %q", results[0].Status, ResultRolledBack)
	}
	if results[0].ErrorMessage != "health degraded post-apply" {
		t.Errorf("ErrorMessage = %q, want %q", results[0].ErrorMessage, "health degraded post-apply")
	}
	if results[0].RolledBackAt == nil {
		t.Error("RolledBackAt is nil, want set")
	}
}

func TestIntegration_List_FiltersByStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, pool, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()
	profileID, deviceID := seedFixtures(t, ctx, pool, tenantID)

	// Two deployments: one planned (default), one marked completed.
	d1, err := r.Create(ctx, tenantID, Deployment{
		ProfileID:                profileID,
		TargetDeviceIDs:          []uuid.UUID{deviceID},
		CanaryDeviceID:           deviceID,
		ValidationMode:           ModeManual,
		ValidationTimeoutSeconds: 1800,
		FailureThresholdPct:      10,
	})
	if err != nil {
		t.Fatalf("Create d1: %v", err)
	}
	d2, err := r.Create(ctx, tenantID, Deployment{
		ProfileID:                profileID,
		TargetDeviceIDs:          []uuid.UUID{deviceID},
		CanaryDeviceID:           deviceID,
		ValidationMode:           ModeManual,
		ValidationTimeoutSeconds: 1800,
		FailureThresholdPct:      10,
	})
	if err != nil {
		t.Fatalf("Create d2: %v", err)
	}
	if err := r.UpdateStatus(ctx, tenantID, d2.ID, StatusCompleted, ""); err != nil {
		t.Fatalf("UpdateStatus d2: %v", err)
	}

	// Unfiltered: both rows, ordered by created_at DESC (d2 first).
	all, err := r.List(ctx, tenantID, ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) < 2 {
		t.Fatalf("List len = %d, want >= 2", len(all))
	}

	// Filter by planned.
	planned, err := r.List(ctx, tenantID, ListFilter{Status: StatusPlanned})
	if err != nil {
		t.Fatalf("List(planned): %v", err)
	}
	foundD1 := false
	for _, d := range planned {
		if d.Status != StatusPlanned {
			t.Errorf("List(planned) returned status %q", d.Status)
		}
		if d.ID == d1.ID {
			foundD1 = true
		}
		if d.ID == d2.ID {
			t.Errorf("List(planned) leaked completed deployment %s", d2.ID)
		}
	}
	if !foundD1 {
		t.Error("List(planned) did not include the planned deployment")
	}

	// Filter by completed.
	completed, err := r.List(ctx, tenantID, ListFilter{Status: StatusCompleted})
	if err != nil {
		t.Fatalf("List(completed): %v", err)
	}
	foundD2 := false
	for _, d := range completed {
		if d.Status != StatusCompleted {
			t.Errorf("List(completed) returned status %q", d.Status)
		}
		if d.ID == d2.ID {
			foundD2 = true
		}
	}
	if !foundD2 {
		t.Error("List(completed) did not include d2")
	}
}

func TestIntegration_RLS_IsolatesDeploymentsAcrossTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()

	r, pool, tenantA, tenantB, cleanup := setupRLSRepo(t)
	defer cleanup()

	// Seed tenant A fixtures + a deployment.
	profileA, deviceA := seedFixtures(t, ctx, pool, tenantA)
	created, err := r.Create(ctx, tenantA, Deployment{
		ProfileID:                profileA,
		TargetDeviceIDs:          []uuid.UUID{deviceA},
		CanaryDeviceID:           deviceA,
		ValidationMode:           ModeManual,
		ValidationTimeoutSeconds: 1800,
		FailureThresholdPct:      10,
	})
	if err != nil {
		t.Fatalf("Create (tenant A): %v", err)
	}

	// Tenant B must not see the tenant A deployment.
	if _, err := r.FindByID(ctx, tenantB, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FindByID cross-tenant err = %v, want ErrNotFound", err)
	}
	listB, err := r.List(ctx, tenantB, ListFilter{})
	if err != nil {
		t.Fatalf("List (tenant B): %v", err)
	}
	for _, d := range listB {
		if d.ID == created.ID {
			t.Errorf("List leaked tenant A deployment %s to tenant B", d.ID)
		}
	}

	// Tenant B mutations cannot reach the tenant A row — ErrNotFound via the
	// conflation contract (existence of the target is not distinguishable
	// from RLS filtering).
	if err := r.UpdateStatus(ctx, tenantB, created.ID, StatusCanaryRunning, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateStatus cross-tenant err = %v, want ErrNotFound", err)
	}
	if err := r.SetCanaryStarted(ctx, tenantB, created.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetCanaryStarted cross-tenant err = %v, want ErrNotFound", err)
	}

	// Tenant A can still see its own deployment, and cross-tenant listing of
	// deployment_results is also isolated.
	if _, err := r.FindByID(ctx, tenantA, created.ID); err != nil {
		t.Fatalf("tenant A must still see its own deployment: %v", err)
	}

	if err := r.UpsertResult(ctx, tenantA, created.ID, deviceA, Result{
		IsCanary: true,
		Status:   ResultApplying,
	}); err != nil {
		t.Fatalf("UpsertResult (tenant A): %v", err)
	}
	resultsB, err := r.ListResults(ctx, tenantB, created.ID)
	if err != nil {
		t.Fatalf("ListResults (tenant B): %v", err)
	}
	if len(resultsB) != 0 {
		t.Errorf("ListResults (tenant B) leaked %d rows, want 0", len(resultsB))
	}
}
