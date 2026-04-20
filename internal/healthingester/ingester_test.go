// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package healthingester

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

func TestSummarize(t *testing.T) {
	snap := &lmdmv1.HealthSnapshot{
		Battery: &lmdmv1.BatteryHealth{Present: true, HealthPct: 78},
		Disks: []*lmdmv1.DiskHealth{
			{Name: "sda", Score: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE},
			{Name: "sdb", Score: lmdmv1.HealthScore_HEALTH_SCORE_GREEN},
			{Name: "sdc", Score: lmdmv1.HealthScore_HEALTH_SCORE_RED},
		},
		FirmwareUpdates: []*lmdmv1.FirmwareUpdate{
			{DeviceName: "BIOS", Severity: "critical"},
			{DeviceName: "TPM", Severity: "low"},
		},
	}
	got := summarize(snap)
	if got.batteryPct == nil || *got.batteryPct != 78 {
		t.Fatalf("batteryPct: got %v, want 78", got.batteryPct)
	}
	if got.criticalDisks != 1 || got.warningDisks != 1 {
		t.Fatalf("disks: critical=%d warning=%d, want 1/1", got.criticalDisks, got.warningDisks)
	}
	if got.fwupdUpdates != 2 || got.fwupdCritical != 1 {
		t.Fatalf("firmware: total=%d critical=%d, want 2/1", got.fwupdUpdates, got.fwupdCritical)
	}
}

func TestSummarizeBatteryAbsent(t *testing.T) {
	snap := &lmdmv1.HealthSnapshot{
		Battery: &lmdmv1.BatteryHealth{Present: false, HealthPct: 0},
	}
	got := summarize(snap)
	if got.batteryPct != nil {
		t.Fatalf("batteryPct should be nil when battery absent, got %v", *got.batteryPct)
	}
}

func TestHealthScoreToDB(t *testing.T) {
	cases := []struct {
		in   lmdmv1.HealthScore
		want int16
	}{
		{lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED, 0},
		{lmdmv1.HealthScore_HEALTH_SCORE_GREEN, 0},
		{lmdmv1.HealthScore_HEALTH_SCORE_ORANGE, 1},
		{lmdmv1.HealthScore_HEALTH_SCORE_RED, 2},
	}
	for _, c := range cases {
		if got := healthScoreToDB(c.in); got != c.want {
			t.Errorf("healthScoreToDB(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestIntegrationHealthIngester_PersistsSnapshot(t *testing.T) {
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
		Hostname: "PC-HEALTH", AgentPubkeyEd25519: []byte("ed-h"), AgentPubkeyMLDSA: []byte("ml-h"),
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

	snap := &lmdmv1.HealthSnapshot{
		DeviceId:     &lmdmv1.DeviceID{Id: deviceID.String()},
		Timestamp:    timestamppb.New(time.Now().UTC()),
		OverallScore: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		Battery:      &lmdmv1.BatteryHealth{Present: true, HealthPct: 78, Score: lmdmv1.HealthScore_HEALTH_SCORE_GREEN},
		Disks: []*lmdmv1.DiskHealth{
			{Name: "sda", Score: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE},
			{Name: "sdb", Score: lmdmv1.HealthScore_HEALTH_SCORE_GREEN},
		},
		FirmwareUpdates: []*lmdmv1.FirmwareUpdate{
			{DeviceName: "BIOS", Severity: "critical", CurrentVersion: "1.0", AvailableVersion: "1.1"},
		},
	}
	data, _ := proto.Marshal(snap)
	if err := plainNC.Publish("fleet.agent."+deviceID.String()+".health", data); err != nil {
		t.Fatal(err)
	}
	_ = plainNC.Flush()

	// Poll for the inserted snapshot row.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM health_snapshots WHERE device_id = $1`, deviceID).Scan(&count); err == nil && count == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Assert health_snapshots row.
	var (
		overall      int16
		batteryPct   *int32
		critical     int32
		warning      int32
		fwupdTotal   int32
		fwupdCrit    int32
		snapshotJSON []byte
	)
	if err := pool.QueryRow(ctx, `
		SELECT overall_score, battery_health_pct, critical_disk_count, warning_disk_count,
		       fwupd_updates_count, fwupd_critical_count, snapshot
		FROM health_snapshots WHERE device_id = $1
	`, deviceID).Scan(&overall, &batteryPct, &critical, &warning, &fwupdTotal, &fwupdCrit, &snapshotJSON); err != nil {
		t.Fatalf("health_snapshots row not found: %v", err)
	}
	if overall != 1 {
		t.Errorf("overall_score: got %d, want 1 (ORANGE)", overall)
	}
	if batteryPct == nil || *batteryPct != 78 {
		t.Errorf("battery_health_pct: got %v, want 78", batteryPct)
	}
	if critical != 0 || warning != 1 {
		t.Errorf("disk counts: critical=%d warning=%d, want 0/1", critical, warning)
	}
	if fwupdTotal != 1 || fwupdCrit != 1 {
		t.Errorf("firmware counts: total=%d critical=%d, want 1/1", fwupdTotal, fwupdCrit)
	}

	// Sanity-check the JSONB content has at least the device_id.
	var asMap map[string]any
	if err := json.Unmarshal(snapshotJSON, &asMap); err != nil {
		t.Fatalf("snapshot is not valid JSON: %v", err)
	}
	if _, ok := asMap["deviceId"]; !ok {
		t.Errorf("snapshot JSON missing deviceId field; got keys: %v", keys(asMap))
	}

	// Assert devices summary columns are updated.
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
	if lastScore == nil || *lastScore != 1 {
		t.Errorf("devices.last_health_score: got %v, want 1", lastScore)
	}
	if devBatteryPct == nil || *devBatteryPct != 78 {
		t.Errorf("devices.battery_health_pct: got %v, want 78", devBatteryPct)
	}
	if devFwupd == nil || *devFwupd != 1 {
		t.Errorf("devices.fwupd_updates_count: got %v, want 1", devFwupd)
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
