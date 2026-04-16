// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package profiles

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

const defaultTenant = "00000000-0000-0000-0000-000000000000"

func setupRepo(t *testing.T) (*Repository, *pqhybrid.SigningPublicKey, func()) {
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
	priv, pub, _ := pqhybrid.GenerateSigningKey(rand.Reader)

	cleanup := func() {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancel()
	}
	return NewRepository(pool, priv), pub, cleanup
}

func TestIntegrationCreateAndFind(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, pub, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	yamlContent := []byte("kind: profile\nmetadata:\n  name: test-profile\n  version: \"1.0\"\n  description: \"test\"\npolicies: []\n")

	p, err := r.Create(context.Background(), tenantID, yamlContent)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.Name != "test-profile" || p.Version != "1.0" {
		t.Errorf("profile = %+v", p)
	}
	if len(p.SignatureEd25519) == 0 || len(p.SignatureMLDSA) == 0 {
		t.Error("profile must be signed at creation time")
	}

	// Verify the signature with the server's pubkey.
	sig := &pqhybrid.HybridSignature{
		Ed25519: p.SignatureEd25519,
		MLDSA:   p.SignatureMLDSA,
	}
	if err := pqhybrid.Verify(pub, yamlContent, sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// FindByID.
	got, err := r.FindByID(context.Background(), tenantID, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name != "test-profile" {
		t.Errorf("FindByID.Name = %q", got.Name)
	}
}

func TestIntegrationAssignProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, _, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	p, err := r.Create(context.Background(), tenantID, []byte("kind: profile\nmetadata:\n  name: assign-test\n  version: \"1.0\"\npolicies: []\n"))
	if err != nil {
		t.Fatal(err)
	}

	deviceID := uuid.New()
	if err := r.Assign(context.Background(), tenantID, p.ID, "device", deviceID); err != nil {
		t.Fatalf("Assign: %v", err)
	}

	profiles, err := r.ListAssigned(context.Background(), tenantID, "device", deviceID)
	if err != nil {
		t.Fatalf("ListAssigned: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "assign-test" {
		t.Errorf("assigned = %+v", profiles)
	}
}
