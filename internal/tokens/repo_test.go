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
