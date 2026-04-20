// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package patchingester

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
	"github.com/cto-externe/lmdm/internal/natsbus"
)

func TestIntegrationPatchIngesterPersists(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("lmdm"), postgres.WithUsername("lmdm"), postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)))
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

	natsReq := testcontainers.ContainerRequest{
		Image: "nats:2.10-alpine", ExposedPorts: []string{"4222/tcp"},
		Cmd: []string{"-js"}, WaitingFor: wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	natsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: natsReq, Started: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = natsC.Terminate(ctx) })
	natsHost, _ := natsC.Host(ctx)
	natsPort, _ := natsC.MappedPort(ctx, "4222/tcp")
	natsURL := "nats://" + natsHost + ":" + natsPort.Port()

	bus, err := natsbus.Connect(ctx, natsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}

	// Seed device.
	repo := devices.NewRepository(pool)
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	deviceID := uuid.New()
	if err := repo.Insert(ctx, &devices.Device{
		ID: deviceID, TenantID: tenantID, Type: devices.TypeWorkstation,
		Hostname: "PC-PATCH", AgentPubkeyEd25519: []byte("ed-p"), AgentPubkeyMLDSA: []byte("ml-p"),
	}); err != nil {
		t.Fatal(err)
	}

	ing := New(bus, pool)
	if err := ing.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer ing.Stop()

	plainNC, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer plainNC.Close()

	report := &lmdmv1.PatchReport{
		DeviceId:  &lmdmv1.DeviceID{Id: deviceID.String()},
		Timestamp: timestamppb.New(time.Now().UTC()),
		Updates: []*lmdmv1.AvailableUpdate{
			{Name: "openssl", CurrentVersion: "3.0.2-15", AvailableVersion: "3.0.2-16", Security: true, Source: "apt"},
			{Name: "curl", CurrentVersion: "7.81.0-15", AvailableVersion: "7.81.0-16", Security: false, Source: "apt"},
		},
		RebootRequired: true,
	}
	data, _ := proto.Marshal(report)
	if err := plainNC.Publish("fleet.agent."+deviceID.String()+".patches", data); err != nil {
		t.Fatal(err)
	}
	_ = plainNC.Flush()

	// Poll device_updates.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM device_updates WHERE device_id = $1`, deviceID).Scan(&count)
		if err == nil && count == 2 {
			// Also check reboot_required on device.
			var reboot bool
			_ = pool.QueryRow(ctx, `SELECT reboot_required FROM devices WHERE id = $1`, deviceID).Scan(&reboot)
			if reboot {
				return // success
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("device_updates not populated within 5s")
}
