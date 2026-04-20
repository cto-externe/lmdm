// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package commandresultsingester

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
	"github.com/cto-externe/lmdm/internal/deployments"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/natsbus"
)

// spyEngine captures events posted by the ingester for assertion. It
// implements EngineEvents with a buffered channel the test can drain.
type spyEngine struct {
	ch chan deployments.Event
}

func newSpyEngine() *spyEngine {
	return &spyEngine{ch: make(chan deployments.Event, 16)}
}

func (s *spyEngine) Events() chan<- deployments.Event { return s.ch }

func TestMarshalHealthChecks(t *testing.T) {
	hcs := []*lmdmv1.HealthCheckResult{
		{Name: "ping", Passed: true, DurationMs: 12},
		{Name: "dns", Passed: false, Detail: "timeout"},
	}
	got := marshalHealthChecks(hcs)
	if len(got) == 0 {
		t.Fatal("marshalHealthChecks returned empty slice for non-empty input")
	}
	var arr []map[string]any
	if err := json.Unmarshal(got, &arr); err != nil {
		t.Fatalf("output is not a valid JSON array: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("array length: got %d, want 2", len(arr))
	}
	if arr[0]["name"] != "ping" || arr[0]["passed"] != true {
		t.Errorf("arr[0] unexpected: %+v", arr[0])
	}
	if arr[1]["name"] != "dns" || arr[1]["detail"] != "timeout" {
		t.Errorf("arr[1] unexpected: %+v", arr[1])
	}
}

func TestMarshalHealthChecksEmpty(t *testing.T) {
	if got := marshalHealthChecks(nil); got != nil {
		t.Errorf("marshalHealthChecks(nil) = %q, want nil", got)
	}
	if got := marshalHealthChecks([]*lmdmv1.HealthCheckResult{}); got != nil {
		t.Errorf("marshalHealthChecks([]) = %q, want nil", got)
	}
}

func TestIntegrationCommandResultsIngester_ForwardsDeviceResult(t *testing.T) {
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

	// Seed a device.
	repo := devices.NewRepository(pool)
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	deviceID := uuid.New()
	if err := repo.Insert(ctx, &devices.Device{
		ID: deviceID, TenantID: tenantID, Type: devices.TypeWorkstation,
		Hostname: "PC-CMDRES", AgentPubkeyEd25519: []byte("ed-c"), AgentPubkeyMLDSA: []byte("ml-c"),
	}); err != nil {
		t.Fatal(err)
	}

	spy := newSpyEngine()
	ing := New(bus, repo, spy)
	if err := ing.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer ing.Stop()

	plainNC, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer plainNC.Close()

	deploymentID := uuid.New()
	snapshotID := "snap-abc123"
	result := &lmdmv1.CommandResult{
		CommandId:    "cmd-1",
		DeviceId:     &lmdmv1.DeviceID{Id: deviceID.String()},
		Timestamp:    timestamppb.New(time.Now().UTC()),
		Success:      false,
		Error:        "health checks failed",
		DurationMs:   1234,
		SnapshotId:   snapshotID,
		DeploymentId: &lmdmv1.DeploymentID{Id: deploymentID.String()},
		IsCanary:     true,
		HealthChecks: []*lmdmv1.HealthCheckResult{
			{Name: "ping-gw", Passed: true, DurationMs: 8},
			{Name: "dns-internal", Passed: false, Detail: "nxdomain"},
		},
	}
	data, err := proto.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := plainNC.Publish("fleet.agent."+deviceID.String()+".command-result", data); err != nil {
		t.Fatal(err)
	}
	_ = plainNC.Flush()

	// Wait for the forwarded event.
	var ev deployments.Event
	select {
	case ev = <-spy.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for DeviceResult event on spy engine")
	}

	got, ok := ev.(deployments.DeviceResult)
	if !ok {
		t.Fatalf("event type: got %T, want deployments.DeviceResult", ev)
	}
	if got.DeploymentID != deploymentID {
		t.Errorf("DeploymentID: got %v, want %v", got.DeploymentID, deploymentID)
	}
	if got.DeviceID != deviceID {
		t.Errorf("DeviceID: got %v, want %v", got.DeviceID, deviceID)
	}
	if got.Success {
		t.Error("Success: got true, want false")
	}
	if !got.RolledBack {
		t.Error("RolledBack: got false, want true (!success && snapshot_id != \"\")")
	}
	if got.ErrorMessage != "health checks failed" {
		t.Errorf("ErrorMessage: got %q, want %q", got.ErrorMessage, "health checks failed")
	}
	if got.SnapshotID != snapshotID {
		t.Errorf("SnapshotID: got %q, want %q", got.SnapshotID, snapshotID)
	}
	if len(got.HealthCheckResults) == 0 {
		t.Fatal("HealthCheckResults: empty, want JSON array bytes")
	}
	var hcArr []map[string]any
	if err := json.Unmarshal(got.HealthCheckResults, &hcArr); err != nil {
		t.Fatalf("HealthCheckResults is not valid JSON: %v", err)
	}
	if len(hcArr) != 2 {
		t.Fatalf("HealthCheckResults length: got %d, want 2", len(hcArr))
	}
	if hcArr[0]["name"] != "ping-gw" || hcArr[1]["name"] != "dns-internal" {
		t.Errorf("HealthCheckResults names: got %v, want [ping-gw dns-internal]", hcArr)
	}

	// A result with no deployment_id should be Ack'd and dropped — no event.
	adhoc := &lmdmv1.CommandResult{
		CommandId: "cmd-adhoc",
		DeviceId:  &lmdmv1.DeviceID{Id: deviceID.String()},
		Timestamp: timestamppb.New(time.Now().UTC()),
		Success:   true,
	}
	data2, _ := proto.Marshal(adhoc)
	if err := plainNC.Publish("fleet.agent."+deviceID.String()+".command-result", data2); err != nil {
		t.Fatal(err)
	}
	_ = plainNC.Flush()

	select {
	case ev := <-spy.ch:
		t.Fatalf("unexpected event for ad-hoc (no deployment_id) result: %+v", ev)
	case <-time.After(500 * time.Millisecond):
		// expected: no event forwarded
	}
}
