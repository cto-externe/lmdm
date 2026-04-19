// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package healthretention

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
)

// setupPool spins up a Postgres testcontainer, runs migrations, opens a pool,
// seeds one device under the default Community tenant, and returns the pool
// plus the seeded device id. Cleanup is registered on t.
func setupPool(t *testing.T) (*db.Pool, uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("lmdm"),
		postgres.WithUsername("lmdm"),
		postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })

	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	deviceID := uuid.New()
	repo := devices.NewRepository(pool)
	if err := repo.Insert(ctx, &devices.Device{
		ID:                 deviceID,
		TenantID:           tenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           "PC-RETENTION",
		AgentPubkeyEd25519: []byte("ed-r"),
		AgentPubkeyMLDSA:   []byte("ml-r"),
	}); err != nil {
		t.Fatal(err)
	}

	return pool, deviceID
}

// insertSnapshot inserts a single health_snapshots row with an explicit ts.
// Bypasses RLS by using the pool owner directly (matches how the pruner runs).
func insertSnapshot(t *testing.T, pool *db.Pool, deviceID uuid.UUID, ts time.Time) {
	t.Helper()
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		INSERT INTO health_snapshots (tenant_id, device_id, ts, overall_score, snapshot)
		VALUES ($1, $2, $3, 0, '{}'::jsonb)
	`, tenantID, deviceID, ts)
	if err != nil {
		t.Fatalf("insert snapshot at ts=%s: %v", ts, err)
	}
}

func countSnapshots(t *testing.T, pool *db.Pool, deviceID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM health_snapshots WHERE device_id = $1`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIntegrationPruner_DeletesOldSnapshots_KeepsRecent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	pool, deviceID := setupPool(t)

	now := time.Now().UTC()
	insertSnapshot(t, pool, deviceID, now.Add(-100*24*time.Hour)) // older than 90d → should be deleted
	insertSnapshot(t, pool, deviceID, now.Add(-30*24*time.Hour))  // recent → should remain
	insertSnapshot(t, pool, deviceID, now)                        // now → should remain

	if got := countSnapshots(t, pool, deviceID); got != 3 {
		t.Fatalf("seed count: got %d, want 3", got)
	}

	p := New(pool, 90*24*time.Hour, 24*time.Hour)
	deleted, err := p.PruneOnce(context.Background())
	if err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted: got %d, want 1", deleted)
	}
	if got := countSnapshots(t, pool, deviceID); got != 2 {
		t.Errorf("remaining: got %d, want 2", got)
	}

	// Confirm the 100-day-old row in particular is gone (oldest remaining ts > 90 days ago).
	var oldestTS time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT MIN(ts) FROM health_snapshots WHERE device_id = $1`, deviceID).Scan(&oldestTS); err != nil {
		t.Fatal(err)
	}
	cutoff := now.Add(-90 * 24 * time.Hour)
	if oldestTS.Before(cutoff) {
		t.Errorf("oldest remaining ts %s is before cutoff %s — old row not pruned", oldestTS, cutoff)
	}
}

func TestIntegrationPruner_NoOldRows_DeletesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	pool, deviceID := setupPool(t)

	now := time.Now().UTC()
	insertSnapshot(t, pool, deviceID, now.Add(-30*24*time.Hour))
	insertSnapshot(t, pool, deviceID, now.Add(-1*24*time.Hour))

	p := New(pool, 90*24*time.Hour, 24*time.Hour)
	deleted, err := p.PruneOnce(context.Background())
	if err != nil {
		t.Fatalf("PruneOnce: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted: got %d, want 0", deleted)
	}
	if got := countSnapshots(t, pool, deviceID); got != 2 {
		t.Errorf("remaining: got %d, want 2", got)
	}
}
