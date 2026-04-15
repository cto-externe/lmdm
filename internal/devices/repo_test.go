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
