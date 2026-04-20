// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package revocation

import (
	"context"
	"errors"
	"sort"
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
	return New(pool), cleanup
}

// setupRLSRepo spins up Postgres, runs migrations, seeds two tenants, creates
// the non-owner lmdm_app role with FORCE ROW LEVEL SECURITY on the
// revoked_certificates table, then returns a Repository backed by a pool
// connected as lmdm_app. Superuser connections bypass RLS so the
// cross-tenant assertions would otherwise be vacuous.
func setupRLSRepo(t *testing.T) (*Repository, uuid.UUID, uuid.UUID, func()) {
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
		GRANT SELECT, INSERT, UPDATE, DELETE ON revoked_certificates TO lmdm_app;
		ALTER TABLE revoked_certificates FORCE ROW LEVEL SECURITY;
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
	return New(appPool), tenantA, tenantB, cleanup
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

func TestIntegrationRevoke_InsertsRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	if err := r.Revoke(ctx, tenantID, "serial-abc", nil, nil, "operator_revoke"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Verify via raw SQL that the row exists.
	var serial, reason string
	err := r.Pool().QueryRow(ctx, `
		SELECT serial_number, reason
		FROM revoked_certificates
		WHERE tenant_id = $1 AND serial_number = $2
	`, tenantID, "serial-abc").Scan(&serial, &reason)
	if err != nil {
		t.Fatalf("raw lookup: %v", err)
	}
	if serial != "serial-abc" {
		t.Errorf("serial = %q, want serial-abc", serial)
	}
	if reason != "operator_revoke" {
		t.Errorf("reason = %q, want operator_revoke", reason)
	}
}

func TestIntegrationRevoke_DuplicateReturnsErrAlreadyRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	if err := r.Revoke(ctx, tenantID, "dup-serial", nil, nil, ""); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	err := r.Revoke(ctx, tenantID, "dup-serial", nil, nil, "")
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("second Revoke err = %v, want ErrAlreadyRevoked", err)
	}
}

func TestIntegrationListSerials_ReturnsAll(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	want := []string{"s1", "s2", "s3"}
	for _, s := range want {
		if err := r.Revoke(ctx, tenantID, s, nil, nil, ""); err != nil {
			t.Fatalf("Revoke %s: %v", s, err)
		}
	}

	got, err := r.ListSerials(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListSerials: %v", err)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("got %d serials, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestIntegrationIsRevoked_HappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	if err := r.Revoke(ctx, tenantID, "known", nil, nil, ""); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	ok, err := r.IsRevoked(ctx, tenantID, "known")
	if err != nil {
		t.Fatalf("IsRevoked(known): %v", err)
	}
	if !ok {
		t.Error("IsRevoked(known) = false, want true")
	}

	ok, err = r.IsRevoked(ctx, tenantID, "unknown")
	if err != nil {
		t.Fatalf("IsRevoked(unknown): %v", err)
	}
	if ok {
		t.Error("IsRevoked(unknown) = true, want false")
	}
}

func TestIntegrationRLS_IsolatesCrossTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()

	r, tenantA, tenantB, cleanup := setupRLSRepo(t)
	defer cleanup()

	if err := r.Revoke(ctx, tenantA, "tenant-a-serial", nil, nil, ""); err != nil {
		t.Fatalf("Revoke under tenant A: %v", err)
	}

	// Tenant B must not see tenant A's row.
	listB, err := r.ListSerials(ctx, tenantB)
	if err != nil {
		t.Fatalf("ListSerials tenant B: %v", err)
	}
	if len(listB) != 0 {
		t.Errorf("tenant B ListSerials leaked %v, want empty", listB)
	}

	ok, err := r.IsRevoked(ctx, tenantB, "tenant-a-serial")
	if err != nil {
		t.Fatalf("IsRevoked tenant B: %v", err)
	}
	if ok {
		t.Error("tenant B IsRevoked(tenant-a-serial) = true, want false (RLS leak)")
	}

	// Sanity: tenant A can still see its own row.
	listA, err := r.ListSerials(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListSerials tenant A: %v", err)
	}
	if len(listA) != 1 || listA[0] != "tenant-a-serial" {
		t.Errorf("tenant A ListSerials = %v, want [tenant-a-serial]", listA)
	}
}
