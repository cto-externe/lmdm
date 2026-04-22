// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package rebootingester

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
)

// testEnv holds the shared infra for each sub-test.
type testEnv struct {
	ctx      context.Context
	pool     *db.Pool
	nc       *nats.Conn
	devRepo  *devices.Repository
	tenantID uuid.UUID
}

func setupEnv(t *testing.T) (*testEnv, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)

	// Postgres container.
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

	// NATS container (plain core, no JetStream needed).
	natsReq := testcontainers.ContainerRequest{
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	natsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: natsReq, Started: true,
	})
	if err != nil {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	natsHost, _ := natsC.Host(ctx)
	natsPort, _ := natsC.MappedPort(ctx, "4222/tcp")
	natsURL := "nats://" + natsHost + ":" + natsPort.Port()

	nc, err := nats.Connect(natsURL)
	if err != nil {
		pool.Close()
		_ = pg.Terminate(ctx)
		_ = natsC.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}

	cleanup := func() {
		nc.Close()
		pool.Close()
		_ = pg.Terminate(ctx)
		_ = natsC.Terminate(ctx)
		cancel()
	}

	return &testEnv{
		ctx:      ctx,
		pool:     pool,
		nc:       nc,
		devRepo:  devices.NewRepository(pool),
		tenantID: uuid.MustParse("00000000-0000-0000-0000-000000000000"),
	}, cleanup
}

// insertDevice seeds a device and sets initial reboot state.
func insertDevice(t *testing.T, env *testEnv, rebootRequired bool, deferCount int) uuid.UUID {
	t.Helper()
	deviceID := uuid.New()
	dev := &devices.Device{
		ID:                 deviceID,
		TenantID:           env.tenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           "reboot-test-" + deviceID.String()[:8],
		AgentPubkeyEd25519: []byte("ed25519-pub"),
		AgentPubkeyMLDSA:   []byte("mldsa-pub"),
	}
	if err := env.devRepo.Insert(env.ctx, dev); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if rebootRequired || deferCount > 0 {
		_, err := env.pool.Exec(env.ctx, `
			UPDATE devices
			   SET reboot_required = $2,
			       pending_reboot_defer_count = $3
			 WHERE id = $1
		`, deviceID, rebootRequired, deferCount)
		if err != nil {
			t.Fatalf("seed device state: %v", err)
		}
	}
	return deviceID
}

// publishReport marshals and publishes a RebootReport on the right subject.
func publishReport(t *testing.T, nc *nats.Conn, rep *lmdmv1.RebootReport) {
	t.Helper()
	data, err := proto.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	subject := "status.device." + rep.GetDeviceId().GetId() + ".reboot-report"
	if err := nc.Publish(subject, data); err != nil {
		t.Fatalf("publish: %v", err)
	}
	_ = nc.Flush()
}

func TestIntegrationIngester_Rebooted_ClearsCounters(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	env, cleanup := setupEnv(t)
	defer cleanup()

	deviceID := insertDevice(t, env, true, 3)

	ing := New(env.nc, env.pool, env.devRepo, nil)
	if err := ing.Start(env.ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = ing.Stop() }()

	publishReport(t, env.nc, &lmdmv1.RebootReport{
		DeviceId:    &lmdmv1.DeviceID{Id: deviceID.String()},
		AttemptedAt: timestamppb.New(time.Now().UTC()),
		Outcome:     "rebooted",
		DeferCount:  0,
		Reason:      "patch_required",
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var rebootRequired bool
		var deferCount int
		err := env.pool.QueryRow(env.ctx,
			`SELECT reboot_required, pending_reboot_defer_count FROM devices WHERE id = $1`, deviceID,
		).Scan(&rebootRequired, &deferCount)
		if err == nil && !rebootRequired && deferCount == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("device state not updated within 5s after rebooted report")
}

func TestIntegrationIngester_Deferred_UpdatesCounter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	env, cleanup := setupEnv(t)
	defer cleanup()

	deviceID := insertDevice(t, env, true, 0)

	ing := New(env.nc, env.pool, env.devRepo, nil)
	if err := ing.Start(env.ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = ing.Stop() }()

	publishReport(t, env.nc, &lmdmv1.RebootReport{
		DeviceId:    &lmdmv1.DeviceID{Id: deviceID.String()},
		AttemptedAt: timestamppb.New(time.Now().UTC()),
		Outcome:     "deferred_user_active",
		DeferCount:  2,
		Reason:      "user_active",
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var deferCount int
		var lastDeferred *time.Time
		err := env.pool.QueryRow(env.ctx,
			`SELECT pending_reboot_defer_count, pending_reboot_last_deferred_at FROM devices WHERE id = $1`, deviceID,
		).Scan(&deferCount, &lastDeferred)
		if err == nil && deferCount == 2 && lastDeferred != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("defer counter not updated within 5s")
}

func TestIntegrationIngester_InvalidDeviceID_Swallowed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	env, cleanup := setupEnv(t)
	defer cleanup()

	// Insert a real device so we can confirm its row is untouched.
	deviceID := insertDevice(t, env, true, 1)

	ing := New(env.nc, env.pool, env.devRepo, nil)
	if err := ing.Start(env.ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = ing.Stop() }()

	// Publish report with a bogus device_id.
	bogusID := "not-a-uuid"
	data, _ := proto.Marshal(&lmdmv1.RebootReport{
		DeviceId:    &lmdmv1.DeviceID{Id: bogusID},
		AttemptedAt: timestamppb.New(time.Now().UTC()),
		Outcome:     "rebooted",
	})
	_ = env.nc.Publish("status.device.bogus-device.reboot-report", data)
	_ = env.nc.Flush()

	// Wait long enough for the handler to run.
	time.Sleep(100 * time.Millisecond)

	// The real device must be unchanged.
	var rebootRequired bool
	var deferCount int
	if err := env.pool.QueryRow(env.ctx,
		`SELECT reboot_required, pending_reboot_defer_count FROM devices WHERE id = $1`, deviceID,
	).Scan(&rebootRequired, &deferCount); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !rebootRequired || deferCount != 1 {
		t.Errorf("device state mutated unexpectedly: reboot_required=%v defer_count=%d", rebootRequired, deferCount)
	}
}

func TestIntegrationIngester_ForcedAfterMaxDefers_ClearsCounters(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	env, cleanup := setupEnv(t)
	defer cleanup()

	deviceID := insertDevice(t, env, true, 5)

	ing := New(env.nc, env.pool, env.devRepo, nil)
	if err := ing.Start(env.ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() { _ = ing.Stop() }()

	publishReport(t, env.nc, &lmdmv1.RebootReport{
		DeviceId:    &lmdmv1.DeviceID{Id: deviceID.String()},
		AttemptedAt: timestamppb.New(time.Now().UTC()),
		Outcome:     "forced_after_max_defers",
		DeferCount:  5,
		Reason:      "max_defers_reached",
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var rebootRequired bool
		var deferCount int
		err := env.pool.QueryRow(env.ctx,
			`SELECT reboot_required, pending_reboot_defer_count FROM devices WHERE id = $1`, deviceID,
		).Scan(&rebootRequired, &deferCount)
		if err == nil && !rebootRequired && deferCount == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("device state not cleared within 5s after forced_after_max_defers report")
}
