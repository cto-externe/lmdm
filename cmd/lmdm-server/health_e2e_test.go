// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/api"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/healthingester"
	"github.com/cto-externe/lmdm/internal/natsbus"
	profilesRepo "github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/server"
	"github.com/cto-externe/lmdm/internal/serverkey"
	"github.com/cto-externe/lmdm/internal/tokens"
)

// TestIntegrationHealthSnapshotFlowToRESTAPI exercises the full
// agent-publish -> healthingester -> REST-read pipeline:
//
//  1. publish a HealthSnapshot proto on fleet.agent.<deviceID>.health
//  2. wait for the ingester to persist it
//  3. read it back via GET /api/v1/devices/<id>/health
//  4. verify the denormalized columns on devices were updated
func TestIntegrationHealthSnapshotFlowToRESTAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
		ContainerRequest: natsReq, Started: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = natsC.Terminate(ctx) })
	natsHost, _ := natsC.Host(ctx)
	natsPort, _ := natsC.MappedPort(ctx, "4222/tcp")
	natsURL := "nats://" + natsHost + ":" + natsPort.Port()

	bus, err := natsbus.Connect(ctx, natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}

	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)
	keyPath := t.TempDir() + "/server.key"
	serverPriv, _, err := serverkey.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")

	// Seed a device row directly in the DB. We don't go through the full
	// enroll flow because this test focuses on the health pipeline.
	deviceID := uuid.New()
	if err := deviceRepo.Insert(ctx, &devices.Device{
		ID:                 deviceID,
		TenantID:           tenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           "PC-HEALTH-E2E",
		AgentPubkeyEd25519: []byte("ed-e2e"),
		AgentPubkeyMLDSA:   []byte("ml-e2e"),
	}); err != nil {
		t.Fatal(err)
	}

	// Build server with REST API + health ingester.
	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	mux := http.NewServeMux()
	apiDeps, signer := newTestAPIDeps(t, pool, deviceRepo, tokenRepo,
		profilesRepo.NewRepository(pool, serverPriv), bus.NC(), tenantID)
	mux.Handle("/api/", api.Router(apiDeps))
	srv, err := server.New(httpAddr, grpcAddr, mux)
	if err != nil {
		t.Fatal(err)
	}

	healthIng := healthingester.New(bus, deviceRepo)
	if err := healthIng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer healthIng.Stop()

	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()
	select {
	case e := <-errs:
		t.Fatalf("server: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	// Publish a HealthSnapshot via the bus. The ingester subscribes to
	// fleet.agent.*.health on JetStream, and bus.Publish routes through
	// the JetStream-backed subject.
	snap := &lmdmv1.HealthSnapshot{
		DeviceId:     &lmdmv1.DeviceID{Id: deviceID.String()},
		Timestamp:    timestamppb.New(time.Now().UTC()),
		OverallScore: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		Disks: []*lmdmv1.DiskHealth{
			{
				Name:               "sda",
				Type:               "sata",
				SmartPassed:        true,
				TemperatureCelsius: 32,
				Score:              lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
			},
		},
		Battery: &lmdmv1.BatteryHealth{
			Present:   true,
			HealthPct: 78,
			Score:     lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		FirmwareUpdates: []*lmdmv1.FirmwareUpdate{
			{
				DeviceName:       "BIOS",
				CurrentVersion:   "1.0",
				AvailableVersion: "1.1",
				Severity:         "critical",
			},
		},
	}
	snapData, err := proto.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := bus.NC().Publish("fleet.agent."+deviceID.String()+".health", snapData); err != nil {
		t.Fatal(err)
	}
	_ = bus.NC().Flush()

	baseURL := "http://" + httpAddr
	bearer := testAccessToken(t, signer, tenantID)

	// Poll GET /api/v1/devices/<id>/health until 200 — the ingester is async.
	var (
		body       []byte
		gotStatus  int
		lastErr    error
		gotPayload struct {
			ObservedAt string          `json:"observed_at"`
			Snapshot   json.RawMessage `json:"snapshot"`
		}
	)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/devices/"+deviceID.String()+"/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		gotStatus = resp.StatusCode
		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, &gotPayload); err != nil {
				t.Fatalf("decode response: %v (body=%s)", err, body)
			}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if gotStatus != http.StatusOK {
		t.Fatalf("GET /health never returned 200 within 10s: status=%d body=%s lastErr=%v",
			gotStatus, body, lastErr)
	}

	// observed_at must be a parsable RFC3339 timestamp.
	if _, err := time.Parse(time.RFC3339, gotPayload.ObservedAt); err != nil {
		t.Errorf("observed_at not RFC3339: %q (%v)", gotPayload.ObservedAt, err)
	}

	// snapshot must contain the expected fields. protojson stringifies enums,
	// so overallScore is rendered as "HEALTH_SCORE_RED".
	var snapMap map[string]any
	if err := json.Unmarshal(gotPayload.Snapshot, &snapMap); err != nil {
		t.Fatalf("snapshot not valid JSON: %v (body=%s)", err, gotPayload.Snapshot)
	}
	if got, _ := snapMap["overallScore"].(string); got != "HEALTH_SCORE_RED" {
		t.Errorf("snapshot.overallScore = %q, want HEALTH_SCORE_RED", got)
	}
	battery, ok := snapMap["battery"].(map[string]any)
	if !ok {
		t.Fatalf("snapshot.battery missing or wrong type: %v", snapMap["battery"])
	}
	if got, _ := battery["healthPct"].(float64); got != 78 {
		t.Errorf("snapshot.battery.healthPct = %v, want 78", battery["healthPct"])
	}
	fw, ok := snapMap["firmwareUpdates"].([]any)
	if !ok || len(fw) == 0 {
		t.Fatalf("snapshot.firmwareUpdates missing: %v", snapMap["firmwareUpdates"])
	}
	fw0, _ := fw[0].(map[string]any)
	if got, _ := fw0["severity"].(string); got != "critical" {
		t.Errorf("snapshot.firmwareUpdates[0].severity = %q, want critical", got)
	}

	// Verify denormalized columns on devices were updated.
	var (
		lastAt        *time.Time
		lastScore     *int16
		devBatteryPct *int32
		devFwupd      *int32
	)
	if err := pool.QueryRow(ctx, `
		SELECT last_health_at, last_health_score, battery_health_pct, fwupd_updates_count
		FROM devices WHERE id = $1
	`, deviceID).Scan(&lastAt, &lastScore, &devBatteryPct, &devFwupd); err != nil {
		t.Fatalf("devices row read: %v", err)
	}
	if lastAt == nil {
		t.Error("devices.last_health_at not set")
	}
	if lastScore == nil || *lastScore != 2 {
		t.Errorf("devices.last_health_score: got %v, want 2 (RED)", lastScore)
	}
	if devBatteryPct == nil || *devBatteryPct != 78 {
		t.Errorf("devices.battery_health_pct: got %v, want 78", devBatteryPct)
	}
	if devFwupd == nil || *devFwupd != 1 {
		t.Errorf("devices.fwupd_updates_count: got %v, want 1", devFwupd)
	}
}
