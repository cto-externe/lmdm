// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package tokens

import (
	"context"
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

func TestIntegrationCreateAndConsume(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	plaintext, tok, err := r.Create(context.Background(), CreateRequest{
		TenantID:    tenantID,
		Description: "test",
		GroupIDs:    []string{"g1", "g2"},
		MaxUses:     2,
		TTL:         time.Hour,
		CreatedBy:   "tester",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if plaintext == "" || tok.ID == uuid.Nil {
		t.Fatal("Create returned empty values")
	}

	// First consume succeeds.
	got, err := r.ValidateAndConsume(context.Background(), plaintext)
	if err != nil {
		t.Fatalf("ValidateAndConsume #1: %v", err)
	}
	if got.ID != tok.ID {
		t.Fatal("returned token id mismatch")
	}
	if got.UsedCount != 1 {
		t.Errorf("UsedCount = %d, want 1", got.UsedCount)
	}

	// Second consume succeeds (max_uses=2).
	if _, err := r.ValidateAndConsume(context.Background(), plaintext); err != nil {
		t.Fatalf("ValidateAndConsume #2: %v", err)
	}

	// Third consume fails (max_uses exhausted).
	_, err = r.ValidateAndConsume(context.Background(), plaintext)
	if err != ErrTokenInvalid {
		t.Fatalf("ValidateAndConsume #3: got %v, want ErrTokenInvalid", err)
	}
}

func TestIntegrationValidateAndConsumeRejectsExpired(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	plaintext, _, err := r.Create(context.Background(), CreateRequest{
		TenantID:    tenantID,
		Description: "expired",
		MaxUses:     1,
		TTL:         -time.Second, // already expired
		CreatedBy:   "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ValidateAndConsume(context.Background(), plaintext)
	if err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestIntegrationValidateAndConsumeRejectsRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	plaintext, tok, err := r.Create(context.Background(), CreateRequest{
		TenantID:    tenantID,
		Description: "to-revoke",
		MaxUses:     5,
		TTL:         time.Hour,
		CreatedBy:   "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke(context.Background(), tenantID, tok.ID); err != nil {
		t.Fatal(err)
	}
	_, err = r.ValidateAndConsume(context.Background(), plaintext)
	if err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid after revoke, got %v", err)
	}
}

func TestIntegrationRLSIsolatesTokens(t *testing.T) {
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

	// Seed tenants and create a non-owner role with FORCE RLS on the table.
	_, err = pool.Exec(ctx, `
		INSERT INTO tenants (id, name) VALUES
			('11111111-1111-1111-1111-111111111111', 'tenant-a'),
			('22222222-2222-2222-2222-222222222222', 'tenant-b');
		CREATE ROLE lmdm_app LOGIN PASSWORD 'appsecret';
		GRANT SELECT, INSERT, UPDATE ON enrollment_tokens TO lmdm_app;
		ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;
	`)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	appPool, err := db.Open(ctx, replaceUserTokens(dsn, "lmdm_app", "appsecret"))
	if err != nil {
		t.Fatalf("open app pool: %v", err)
	}
	defer appPool.Close()

	conn, err := appPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()

	// Tenant A: insert a token row.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantA.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO enrollment_tokens
		    (tenant_id, secret_hash, description, group_ids, max_uses, expires_at, created_by)
		VALUES (lmdm_current_tenant(), '\x00aa', 'a-token', '{}', 1, NOW() + INTERVAL '1 hour', 'test')
	`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM enrollment_tokens`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("tenant A sees %d rows, want 1", count)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Tenant B: must see zero tokens.
	tx2, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx2.Rollback(ctx) }()
	if _, err := tx2.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantB.String()); err != nil {
		t.Fatal(err)
	}
	if err := tx2.QueryRow(ctx, `SELECT count(*) FROM enrollment_tokens`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("tenant B sees %d rows, want 0 (RLS leak!)", count)
	}
}

func replaceUserTokens(dsn, user, password string) string {
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
