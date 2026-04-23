// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/natsbus"
	"github.com/cto-externe/lmdm/internal/patchschedule"
)

// TestIntegrationPatchE2E verifies the full patch scheduling flow:
//   DB schedule (next_fire_at already due) → engine tick →
//   NATS ApplyPatchesCommand published with the right reboot_policy.
func TestIntegrationPatchE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// ── Spin up postgres ──────────────────────────────────────────────────────
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
	t.Cleanup(func() { pool.Close() })

	// ── Spin up NATS ──────────────────────────────────────────────────────────
	natsReq := testcontainers.ContainerRequest{
		Image: "nats:2.10-alpine", ExposedPorts: []string{"4222/tcp"},
		Cmd:        []string{"-js"},
		WaitingFor: wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
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
	t.Cleanup(func() { bus.Close() })
	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}

	// ── Seed tenant T1 with reboot_policy = 'immediate_after_apply' ───────────
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	patchRepo := patchschedule.NewRepository(pool)
	if err := patchRepo.UpdateTenantPolicy(ctx, tenantID, patchschedule.RebootPolicyImmediateAfterApply, nil); err != nil {
		t.Fatalf("UpdateTenantPolicy: %v", err)
	}

	// ── Seed device D1 in tenant T1 ───────────────────────────────────────────
	deviceRepo := devices.NewRepository(pool)
	d1ID := uuid.New()
	if err := deviceRepo.Insert(ctx, &devices.Device{
		ID:                 d1ID,
		TenantID:           tenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           "patch-e2e-" + d1ID.String()[:8],
		AgentPubkeyEd25519: []byte("ed-patch-" + d1ID.String()),
		AgentPubkeyMLDSA:   []byte("ml-patch-" + d1ID.String()),
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// ── Subscribe to D1's command subject BEFORE creating the schedule ────────
	nc := bus.NC()
	sub, err := nc.SubscribeSync("fleet.agent." + d1ID.String() + ".commands")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}

	// ── Create schedule already due (next_fire_at = now - 1 min) ─────────────
	originalNextFire := time.Now().UTC().Add(-time.Minute)
	sched, err := patchRepo.Create(ctx, patchschedule.NewSchedule{
		TenantID:           tenantID,
		DeviceID:           &d1ID,
		CronExpr:           "0 3 * * *",
		FilterSecurityOnly: true,
	}, originalNextFire)
	if err != nil {
		t.Fatalf("Create schedule: %v", err)
	}

	// ── Start the engine with a 100 ms tick interval ──────────────────────────
	resolver := patchschedule.NewResolver(pool.Pool)
	engine := patchschedule.NewEngine(patchRepo, nc, resolver, deviceRepo, 100*time.Millisecond)

	engineCtx, cancelEngine := context.WithCancel(context.Background())
	t.Cleanup(cancelEngine)
	go func() { _ = engine.Run(engineCtx) }()

	// ── Wait up to 5 s for the ApplyPatchesCommand ────────────────────────────
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("no command received within 5s: %v", err)
	}

	var env lmdmv1.CommandEnvelope
	if err := proto.Unmarshal(msg.Data, &env); err != nil {
		t.Fatalf("unmarshal CommandEnvelope: %v", err)
	}

	// ── Assert envelope content ───────────────────────────────────────────────
	ap := env.GetApplyPatches()
	if ap == nil {
		t.Fatal("expected ApplyPatchesCommand, got nil")
	}
	if !ap.GetFilter().GetSecurityOnly() {
		t.Errorf("security_only: got false, want true")
	}
	if ap.GetRebootPolicy() != patchschedule.RebootPolicyImmediateAfterApply {
		t.Errorf("reboot_policy: got %q, want %q", ap.GetRebootPolicy(), patchschedule.RebootPolicyImmediateAfterApply)
	}

	// ── Assert DB state updated ───────────────────────────────────────────────
	deadline := time.Now().Add(5 * time.Second)
	var lastStatus string
	var newNextFire time.Time
	for time.Now().Before(deadline) {
		updated, err := patchRepo.FindByID(ctx, sched.ID)
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if updated.LastRunStatus != nil {
			lastStatus = *updated.LastRunStatus
			newNextFire = updated.NextFireAt
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastStatus != patchschedule.RunStatusOK {
		t.Errorf("last_run_status: got %q, want %q", lastStatus, patchschedule.RunStatusOK)
	}
	if !newNextFire.After(originalNextFire) {
		t.Errorf("next_fire_at should advance beyond %v, got %v", originalNextFire, newNextFire)
	}
}
