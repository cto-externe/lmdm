// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package audit

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/db"
)

const defaultTenant = "00000000-0000-0000-0000-000000000000"

// setupWriter spins up Postgres, runs migrations, and returns a Writer backed
// by the owner pool. This bypasses FORCE ROW LEVEL SECURITY, so it's suitable
// for tests that only need to verify row contents; use setupRLSWriter for
// isolation tests.
func setupWriter(t *testing.T) (*Writer, *db.Pool, func()) {
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
	return NewWriter(pool), pool, cleanup
}

// setTenantGUC sets the lmdm.tenant_id session variable on a pool-level query
// so tests can SELECT rows under the RLS policy. Each call pins a single
// connection via a transaction.
func selectCountByAction(ctx context.Context, t *testing.T, pool *db.Pool, tenantID uuid.UUID, action Action) int {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND action = $2`,
		tenantID, string(action)).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestIntegration_Write_InsertsRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	w, pool, cleanup := setupWriter(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	if err := w.Write(ctx, Event{
		TenantID: tenantID,
		Actor:    ActorSystem,
		Action:   ActionUserLoginSuccess,
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if got := selectCountByAction(ctx, t, pool, tenantID, ActionUserLoginSuccess); got != 1 {
		t.Errorf("count = %d, want 1", got)
	}
}

func TestIntegration_Write_PersistsAllFields(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	w, pool, cleanup := setupWriter(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	userID := uuid.New()
	ctx := context.Background()

	clientIP := net.ParseIP("203.0.113.42")
	details := map[string]any{
		"reason":   "mfa_required",
		"attempts": float64(3),
	}
	if err := w.Write(ctx, Event{
		TenantID:     tenantID,
		Actor:        ActorUser(userID),
		Action:       ActionUserRoleChanged,
		ResourceType: "user",
		ResourceID:   userID.String(),
		SourceIP:     clientIP,
		Details:      details,
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read back under the same tenant via a fresh tenant-scoped tx.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("set_config: %v", err)
	}

	var (
		actor, action             string
		resType, resID            *string
		sourceIP                  *net.IP
		detailsJSON               []byte
	)
	if err := tx.QueryRow(ctx, `
		SELECT actor, action, resource_type, resource_id, host(source_ip)::text, details::text
		FROM audit_log WHERE tenant_id = $1 AND action = $2
	`, tenantID, string(ActionUserRoleChanged)).Scan(
		&actor, &action, &resType, &resID, &sourceIP, &detailsJSON,
	); err != nil {
		// source_ip is INET — pgx returns it as *net.IP via our scan target
		// above when wrapped with host()::text, but INET text can be NULL. If
		// scan shape fails, re-read individually for clearer diagnostics.
		t.Fatalf("scan row: %v", err)
	}

	if actor != ActorUser(userID) {
		t.Errorf("actor = %q, want %q", actor, ActorUser(userID))
	}
	if action != string(ActionUserRoleChanged) {
		t.Errorf("action = %q, want %q", action, ActionUserRoleChanged)
	}
	if resType == nil || *resType != "user" {
		t.Errorf("resource_type = %v, want %q", resType, "user")
	}
	if resID == nil || *resID != userID.String() {
		t.Errorf("resource_id = %v, want %q", resID, userID.String())
	}

	// source_ip: we read host(source_ip)::text, so sourceIP is *net.IP scanned
	// from a text-like column — pgx will actually give a string. Re-query to
	// verify as a plain string to avoid pgx INET->net.IP scan gymnastics.
	var ipStr *string
	if err := tx.QueryRow(ctx, `
		SELECT host(source_ip) FROM audit_log WHERE tenant_id = $1 AND action = $2
	`, tenantID, string(ActionUserRoleChanged)).Scan(&ipStr); err != nil {
		t.Fatalf("scan ip: %v", err)
	}
	if ipStr == nil || *ipStr != "203.0.113.42" {
		t.Errorf("source_ip host() = %v, want 203.0.113.42", ipStr)
	}

	// details: JSON-level equality (column order is not preserved by jsonb).
	var got map[string]any
	if err := json.Unmarshal(detailsJSON, &got); err != nil {
		t.Fatalf("unmarshal details: %v", err)
	}
	if got["reason"] != "mfa_required" || got["attempts"] != float64(3) {
		t.Errorf("details = %v, want reason=mfa_required attempts=3", got)
	}
}

func TestIntegration_Write_HandlesNilDetails(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	w, pool, cleanup := setupWriter(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	if err := w.Write(ctx, Event{
		TenantID: tenantID,
		Actor:    ActorSystem,
		Action:   ActionUserLogout,
		// ResourceType/ID empty; SourceIP nil; Details nil.
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("set_config: %v", err)
	}

	var (
		resType, resID *string
		srcIPNull      bool
		detailsNull    bool
	)
	if err := tx.QueryRow(ctx, `
		SELECT resource_type, resource_id, source_ip IS NULL, details IS NULL
		FROM audit_log WHERE tenant_id = $1 AND action = $2
	`, tenantID, string(ActionUserLogout)).Scan(&resType, &resID, &srcIPNull, &detailsNull); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if resType != nil {
		t.Errorf("resource_type = %v, want NULL", *resType)
	}
	if resID != nil {
		t.Errorf("resource_id = %v, want NULL", *resID)
	}
	if !srcIPNull {
		t.Error("source_ip is not NULL, want NULL")
	}
	if !detailsNull {
		t.Error("details is not NULL, want NULL")
	}
}

// setupRLSWriter mirrors setupRLSRepo from internal/users. It seeds two
// tenants, creates the non-owner lmdm_app role, and forces RLS on audit_log
// so the cross-tenant assertions are meaningful.
func setupRLSWriter(t *testing.T) (*Writer, *db.Pool, uuid.UUID, uuid.UUID, func()) {
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
		GRANT SELECT, INSERT ON audit_log TO lmdm_app;
		GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO lmdm_app;
		ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
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
	return NewWriter(appPool), appPool, tenantA, tenantB, cleanup
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

func TestIntegration_Write_RLS_WritesToCorrectTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	w, pool, tenantA, tenantB, cleanup := setupRLSWriter(t)
	defer cleanup()

	ctx := context.Background()

	// Write under tenant A.
	if err := w.Write(ctx, Event{
		TenantID: tenantA,
		Actor:    ActorSystem,
		Action:   ActionUserLoginSuccess,
		Details:  map[string]any{"note": "tenant-a"},
	}); err != nil {
		t.Fatalf("Write(tenantA): %v", err)
	}

	// Reading as lmdm_app under tenant B's GUC must see zero rows for tenant A's action.
	if got := selectCountByAction(ctx, t, pool, tenantB, ActionUserLoginSuccess); got != 0 {
		t.Errorf("tenant B visibility count = %d, want 0 (RLS should hide tenant A row)", got)
	}

	// Sanity: under tenant A's GUC the row is visible.
	if got := selectCountByAction(ctx, t, pool, tenantA, ActionUserLoginSuccess); got != 1 {
		t.Errorf("tenant A visibility count = %d, want 1", got)
	}

	// Cross-tenant WITH CHECK: attempting to write a row whose tenant_id is B
	// while the GUC is set to A must be rejected (the writer sets the GUC from
	// Event.TenantID, so we emulate a mismatch by a direct SQL probe).
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantA.String()); err != nil {
		t.Fatalf("set_config: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (tenant_id, actor, action) VALUES ($1, 'system', 'rls.probe')
	`, tenantB); err == nil {
		t.Error("INSERT with tenant_id=B under GUC=A succeeded, want RLS WITH CHECK violation")
	}
}
