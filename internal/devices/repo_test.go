package devices

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

func TestIntegrationFindByPubKey(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	pub := []byte("a-unique-ed25519-pub")
	d := &Device{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Type:               TypeWorkstation,
		Hostname:           "PC-002",
		AgentPubkeyEd25519: pub,
		AgentPubkeyMLDSA:   []byte("mldsa-pub"),
	}
	if err := r.Insert(context.Background(), d); err != nil {
		t.Fatal(err)
	}

	got, err := r.FindByEd25519PubKey(context.Background(), pub)
	if err != nil {
		t.Fatalf("FindByEd25519PubKey: %v", err)
	}
	if got.ID != d.ID {
		t.Errorf("ID mismatch: %v vs %v", got.ID, d.ID)
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
