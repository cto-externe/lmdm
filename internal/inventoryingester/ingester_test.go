// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package inventoryingester

import (
	"context"
	"encoding/json"
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

func TestIntegrationInventoryIngesterPersists(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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

	natsReq := testcontainers.ContainerRequest{
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		Cmd:          []string{"-js"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	natsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: natsReq, Started: true,
	})
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

	// Seed a device row so the FK is satisfied.
	repo := devices.NewRepository(pool)
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	deviceID := uuid.New()
	if err := repo.Insert(ctx, &devices.Device{
		ID: deviceID, TenantID: tenantID, Type: devices.TypeWorkstation,
		Hostname:           "PC-INV",
		AgentPubkeyEd25519: []byte("ed-inv"),
		AgentPubkeyMLDSA:   []byte("ml-inv"),
	}); err != nil {
		t.Fatal(err)
	}

	ing := New(bus, repo)
	if err := ing.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer ing.Stop()

	plainNC, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer plainNC.Close()

	rep := &lmdmv1.InventoryReport{
		DeviceId:      &lmdmv1.DeviceID{Id: deviceID.String()},
		Timestamp:     timestamppb.New(time.Now().UTC()),
		IsFull:        true,
		SchemaVersion: 1,
		Hardware: &lmdmv1.HardwareInventory{
			System: &lmdmv1.SystemInfo{Manufacturer: "ACME", Model: "M1", FormFactor: "laptop"},
			Cpu:    &lmdmv1.CPUInfo{Model: "Ryzen 7", Cores: 8, Threads: 16},
		},
		Software: &lmdmv1.SoftwareInventory{
			Os: &lmdmv1.OSInfo{Family: lmdmv1.OSFamily_OS_FAMILY_DEBIAN, Name: "ubuntu", Version: "24.04"},
		},
		Network: &lmdmv1.NetworkInventory{Hostname: "pc-inv"},
	}
	data, err := proto.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	subject := "fleet.agent." + deviceID.String() + ".inventory"
	if err := plainNC.Publish(subject, data); err != nil {
		t.Fatal(err)
	}
	_ = plainNC.Flush()

	// Poll the DB for the stored inventory.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var jsonPayload []byte
		err := pool.QueryRow(ctx,
			`SELECT report_json FROM device_inventory WHERE device_id = $1`, deviceID,
		).Scan(&jsonPayload)
		if err == nil {
			// Verify a couple of path-expressed fields.
			var parsed map[string]any
			if err := json.Unmarshal(jsonPayload, &parsed); err != nil {
				t.Fatalf("invalid JSONB: %v", err)
			}
			hw, _ := parsed["hardware"].(map[string]any)
			cpu, _ := hw["cpu"].(map[string]any)
			if model, _ := cpu["model"].(string); model != "Ryzen 7" {
				t.Fatalf("hardware.cpu.model = %q, want Ryzen 7", model)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("inventory was not persisted within 5s")
}
