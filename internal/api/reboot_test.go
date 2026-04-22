// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/patchschedule"
)

const rebootTestTenant = "00000000-0000-0000-0000-000000000000"

// rebootTestSetup holds the DB, Deps, userID and NATS URL.
type rebootTestSetup struct {
	deps    *Deps
	userID  uuid.UUID
	natsURL string
	pool    *db.Pool
}

// setupRebootDeps spins up Postgres + NATS containers for reboot endpoint tests.
func setupRebootDeps(t *testing.T) (*rebootTestSetup, func()) {
	t.Helper()
	ctx, cancelTimeout := context.WithTimeout(context.Background(), 120*time.Second)

	// Postgres
	pg, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("lmdm"),
		postgres.WithUsername("lmdm"),
		postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		cancelTimeout()
		t.Fatal(err)
	}
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		_ = pg.Terminate(ctx)
		cancelTimeout()
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		cancelTimeout()
		t.Fatal(err)
	}

	// NATS
	natsReq := testcontainers.ContainerRequest{
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	nc, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: natsReq, Started: true,
	})
	if err != nil {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancelTimeout()
		t.Fatal(err)
	}
	host, _ := nc.Host(ctx)
	port, _ := nc.MappedPort(ctx, "4222/tcp")
	natsURL := "nats://" + host + ":" + port.Port()

	// Seed a user row.
	tenantID := uuid.MustParse(rebootTestTenant)
	userID := uuid.New()
	seedCtx := context.Background()
	tx, txErr := pool.Begin(seedCtx)
	if txErr != nil {
		pool.Close()
		_ = pg.Terminate(ctx)
		_ = nc.Terminate(ctx)
		cancelTimeout()
		t.Fatalf("seed begin: %v", txErr)
	}
	if _, execErr := tx.Exec(seedCtx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); execErr != nil {
		_ = tx.Rollback(seedCtx)
		pool.Close()
		_ = pg.Terminate(ctx)
		_ = nc.Terminate(ctx)
		cancelTimeout()
		t.Fatalf("seed set_config: %v", execErr)
	}
	if _, execErr := tx.Exec(seedCtx,
		`INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES ($1, $2, $3, 'unused-hash', 'admin')`,
		userID, tenantID, "reboot-test-"+userID.String()[:8]+"@test.local",
	); execErr != nil {
		_ = tx.Rollback(seedCtx)
		pool.Close()
		_ = pg.Terminate(ctx)
		_ = nc.Terminate(ctx)
		cancelTimeout()
		t.Fatalf("seed user: %v", execErr)
	}
	if commitErr := tx.Commit(seedCtx); commitErr != nil {
		pool.Close()
		_ = pg.Terminate(ctx)
		_ = nc.Terminate(ctx)
		cancelTimeout()
		t.Fatalf("seed commit: %v", commitErr)
	}

	cleanup := func() {
		pool.Close()
		_ = pg.Terminate(ctx)
		_ = nc.Terminate(ctx)
		cancelTimeout()
	}

	setup := &rebootTestSetup{
		deps: &Deps{
			Pool:      pool,
			PatchRepo: patchschedule.NewRepository(pool),
			Devices:   devices.NewRepository(pool),
			TenantID:  tenantID,
		},
		userID:  userID,
		natsURL: natsURL,
		pool:    pool,
	}
	return setup, cleanup
}

// rebootReqWithUser builds a request injected with an admin Principal.
func rebootReqWithUser(method, target string, body []byte, tenantID, userID uuid.UUID) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	p := &auth.Principal{
		UserID:   userID,
		TenantID: tenantID,
		Role:     auth.RoleAdmin,
		Email:    "admin@test.local",
	}
	return r.WithContext(auth.WithPrincipal(r.Context(), p))
}

// dialNATS connects to NATS and subscribes to fleet.agent.*.commands,
// returning the channel and the connection for cleanup.
func subscribeNATSCommands(t *testing.T, url string) (<-chan *nats.Msg, *nats.Conn) {
	t.Helper()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("nats.Connect: %v", err)
	}
	ch := make(chan *nats.Msg, 1)
	if _, err := nc.ChanSubscribe("fleet.agent.*.commands", ch); err != nil {
		nc.Close()
		t.Fatalf("ChanSubscribe: %v", err)
	}
	_ = nc.Flush()
	return ch, nc
}

func TestIntegrationRebootDevice_PublishesCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupRebootDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	// Subscribe before POST.
	ch, subnc := subscribeNATSCommands(t, setup.natsURL)
	defer subnc.Close()
	time.Sleep(100 * time.Millisecond)

	// Wire up a real NATS connection to Deps.
	nc, err := nats.Connect(setup.natsURL)
	if err != nil {
		t.Fatalf("connect NATS for publish: %v", err)
	}
	defer nc.Close()
	d.NATS = nc

	deviceID := uuid.New()
	body, _ := json.Marshal(rebootDeviceRequest{
		Reason:             "patch_required",
		GracePeriodSeconds: 120,
		Force:              true,
	})
	rec := httptest.NewRecorder()
	req := rebootReqWithUser("POST", "/api/v1/devices/"+deviceID.String()+"/reboot", body, d.TenantID, userID)
	req.SetPathValue("id", deviceID.String())
	d.handleRebootDevice(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}

	// Assert message received.
	select {
	case msg := <-ch:
		var env lmdmv1.CommandEnvelope
		if err := proto.Unmarshal(msg.Data, &env); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		reboot := env.GetReboot()
		if reboot == nil {
			t.Fatal("envelope.Reboot is nil")
		}
		if reboot.Reason != "patch_required" {
			t.Errorf("Reason = %q, want %q", reboot.Reason, "patch_required")
		}
		if reboot.GracePeriodSeconds != 120 {
			t.Errorf("GracePeriodSeconds = %d, want 120", reboot.GracePeriodSeconds)
		}
		if !reboot.Force {
			t.Error("Force = false, want true")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("NATS message not received within timeout")
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "published" {
		t.Errorf("status = %v, want 'published'", resp["status"])
	}
	if resp["command_id"] == "" {
		t.Error("command_id is empty")
	}
}

func TestIntegrationRebootDevice_EmptyBody_UsesDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupRebootDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	ch, subnc := subscribeNATSCommands(t, setup.natsURL)
	defer subnc.Close()
	time.Sleep(100 * time.Millisecond)

	nc, err := nats.Connect(setup.natsURL)
	if err != nil {
		t.Fatalf("connect NATS: %v", err)
	}
	defer nc.Close()
	d.NATS = nc

	deviceID := uuid.New()
	rec := httptest.NewRecorder()
	// POST with nil body — should apply defaults.
	req := rebootReqWithUser("POST", "/api/v1/devices/"+deviceID.String()+"/reboot", nil, d.TenantID, userID)
	req.SetPathValue("id", deviceID.String())
	d.handleRebootDevice(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}

	select {
	case msg := <-ch:
		var env lmdmv1.CommandEnvelope
		if err := proto.Unmarshal(msg.Data, &env); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		reboot := env.GetReboot()
		if reboot == nil {
			t.Fatal("envelope.Reboot is nil")
		}
		if reboot.Reason != "admin_triggered" {
			t.Errorf("Reason = %q, want %q", reboot.Reason, "admin_triggered")
		}
		if reboot.GracePeriodSeconds != 300 {
			t.Errorf("GracePeriodSeconds = %d, want 300", reboot.GracePeriodSeconds)
		}
		if reboot.Force {
			t.Error("Force = true, want false")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("NATS message not received within timeout")
	}
}

func TestIntegrationPatchTenantPolicy_Valid(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupRebootDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	window := "0 2 * * 1"
	body, _ := json.Marshal(patchTenantPolicyRequest{
		RebootPolicy:      "next_maintenance_window",
		MaintenanceWindow: &window,
	})
	rec := httptest.NewRecorder()
	req := rebootReqWithUser("PATCH", "/api/v1/tenants/current/reboot-policy", body, d.TenantID, userID)
	d.handlePatchTenantPolicy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Verify via direct SQL.
	var gotPolicy string
	var gotWindow *string
	tenantID := uuid.MustParse(rebootTestTenant)
	if err := setup.pool.QueryRow(context.Background(),
		`SELECT reboot_policy, maintenance_window FROM tenants WHERE id = $1`, tenantID,
	).Scan(&gotPolicy, &gotWindow); err != nil {
		t.Fatalf("reload tenant: %v", err)
	}
	if gotPolicy != "next_maintenance_window" {
		t.Errorf("reboot_policy = %q, want %q", gotPolicy, "next_maintenance_window")
	}
	if gotWindow == nil || *gotWindow != window {
		t.Errorf("maintenance_window = %v, want %q", gotWindow, window)
	}
}

func TestIntegrationPatchTenantPolicy_InvalidPolicy_400(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupRebootDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	body, _ := json.Marshal(patchTenantPolicyRequest{
		RebootPolicy: "bogus_policy",
	})
	rec := httptest.NewRecorder()
	req := rebootReqWithUser("PATCH", "/api/v1/tenants/current/reboot-policy", body, d.TenantID, userID)
	d.handlePatchTenantPolicy(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationPatchTenantPolicy_InvalidCron_400(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupRebootDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	bad := "not-a-cron"
	body, _ := json.Marshal(patchTenantPolicyRequest{
		RebootPolicy:      "immediate_after_apply",
		MaintenanceWindow: &bad,
	})
	rec := httptest.NewRecorder()
	req := rebootReqWithUser("PATCH", "/api/v1/tenants/current/reboot-policy", body, d.TenantID, userID)
	d.handlePatchTenantPolicy(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationPatchDevicePolicyOverride_NullClears(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupRebootDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID
	tenantID := uuid.MustParse(rebootTestTenant)

	// Insert a device.
	deviceID := uuid.New()
	dev := &devices.Device{
		ID:                 deviceID,
		TenantID:           tenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           "override-test-host",
		AgentPubkeyEd25519: []byte("ed25519-pub"),
		AgentPubkeyMLDSA:   []byte("mldsa-pub"),
	}
	if err := d.Devices.Insert(context.Background(), dev); err != nil {
		t.Fatalf("Insert device: %v", err)
	}

	// First PATCH: set an override.
	policy := "immediate_after_apply"
	window := "0 4 * * 5"
	body, _ := json.Marshal(patchDevicePolicyOverrideRequest{
		RebootPolicyOverride:      &policy,
		MaintenanceWindowOverride: &window,
	})
	rec := httptest.NewRecorder()
	req := rebootReqWithUser("PATCH", "/api/v1/devices/"+deviceID.String()+"/reboot-policy", body, d.TenantID, userID)
	req.SetPathValue("id", deviceID.String())
	d.handlePatchDevicePolicyOverride(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("set override status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Verify overrides are set.
	var gotPolicy, gotWindow *string
	if err := setup.pool.QueryRow(context.Background(), `
		SELECT reboot_policy_override, maintenance_window_override
		  FROM devices WHERE id = $1 AND tenant_id = $2
	`, deviceID, tenantID).Scan(&gotPolicy, &gotWindow); err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if gotPolicy == nil || *gotPolicy != policy {
		t.Errorf("reboot_policy_override = %v, want %q", gotPolicy, policy)
	}

	// Second PATCH: send null (JSON null) to clear.
	nullBody := []byte(`{"reboot_policy_override": null, "maintenance_window_override": null}`)
	rec2 := httptest.NewRecorder()
	req2 := rebootReqWithUser("PATCH", "/api/v1/devices/"+deviceID.String()+"/reboot-policy", nullBody, d.TenantID, userID)
	req2.SetPathValue("id", deviceID.String())
	d.handlePatchDevicePolicyOverride(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("clear override status = %d, want 200; body=%s", rec2.Code, rec2.Body.String())
	}

	// Verify cleared.
	if err := setup.pool.QueryRow(context.Background(), `
		SELECT reboot_policy_override, maintenance_window_override
		  FROM devices WHERE id = $1 AND tenant_id = $2
	`, deviceID, tenantID).Scan(&gotPolicy, &gotWindow); err != nil {
		t.Fatalf("reload device after clear: %v", err)
	}
	if gotPolicy != nil {
		t.Errorf("reboot_policy_override after clear = %v, want nil", gotPolicy)
	}
	if gotWindow != nil {
		t.Errorf("maintenance_window_override after clear = %v, want nil", gotWindow)
	}
}
