// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	"github.com/cto-externe/lmdm/internal/api"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/commandresultsingester"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/deployments"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/natsbus"
	profilesRepo "github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/server"
	"github.com/cto-externe/lmdm/internal/serverkey"
	"github.com/cto-externe/lmdm/internal/tokens"
)

// TestIntegrationDeploymentHappyPath drives the full happy-path deployment flow:
//  1. POST /deployments → engine pushes the canary command on
//     fleet.agent.<canary>.commands
//  2. Simulated canary agent publishes a successful CommandResult on the
//     COMMAND_RESULTS stream
//  3. Deployment transitions to awaiting_validation (manual mode)
//  4. POST /deployments/{id}/validate → engine pushes the rollout commands to
//     the remaining devices
//  5. Simulated remaining agents publish successful CommandResults
//  6. Deployment ends in status = "completed" with one success result per device
//
// Everything goes through real HTTP + real NATS (testcontainers). The only
// thing absent is a real agent process — we just synthesize the protobuf
// CommandResult messages a real agent would send.
func TestIntegrationDeploymentHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	deps, signer, tenantID, baseURL, bus, cleanup := setupDeploymentE2EStack(t, ctx)
	defer cleanup()

	// Seed: profile + 3 devices + 1 user (the user is required by the FK on
	// deployments.created_by_user_id; the JWT subject must match).
	userID := seedUserForDeploymentE2E(t, ctx, deps.Pool, tenantID)
	canary := seedDeviceForDeploymentE2E(t, ctx, deps.Pool, tenantID, "canary-host")
	devA := seedDeviceForDeploymentE2E(t, ctx, deps.Pool, tenantID, "device-a")
	devB := seedDeviceForDeploymentE2E(t, ctx, deps.Pool, tenantID, "device-b")
	profileID := seedProfileForDeploymentE2E(t, ctx, deps.Pool, tenantID, "e2e-profile")

	bearer := mintAccessTokenForUser(t, signer, userID, tenantID)

	// Subscribe to all 3 devices' command subjects BEFORE creating the
	// deployment so we don't miss the synchronous canary push.
	nc := bus.NC()
	canarySub := mustSubscribeCommands(t, nc, canary)
	defer func() { _ = canarySub.Unsubscribe() }()
	devASub := mustSubscribeCommands(t, nc, devA)
	defer func() { _ = devASub.Unsubscribe() }()
	devBSub := mustSubscribeCommands(t, nc, devB)
	defer func() { _ = devBSub.Unsubscribe() }()

	// 1. Create deployment.
	body := map[string]any{
		"profile_id":        profileID.String(),
		"canary_device_id":  canary.String(),
		"target_device_ids": []string{canary.String(), devA.String(), devB.String()},
		"validation_mode":   "manual",
	}
	resp := authedPost(t, baseURL+"/api/v1/deployments", bearer,
		"application/json", string(marshalJSONForE2E(t, body)))
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("create deployment got %d: %s", resp.StatusCode, b)
	}
	var created struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if created.Status != "canary_running" {
		t.Fatalf("expected canary_running after create, got %s", created.Status)
	}

	// 2. Receive the canary ApplyProfileCommand.
	canaryCmd := readCommandWithin(t, canarySub, 5*time.Second)
	if canaryCmd == nil {
		t.Fatal("canary did not receive ApplyProfile command")
	}
	if !canaryCmd.GetIsCanary() {
		t.Error("canary command should have IsCanary=true")
	}

	// 3. Publish a successful CommandResult on COMMAND_RESULTS for the canary.
	publishDeploymentResult(t, ctx, bus, canary, canaryCmd.GetCommandId(), created.ID, true, "")

	// 4. Poll until status transitions to awaiting_validation.
	waitForDeploymentStatus(t, baseURL, bearer, created.ID, "awaiting_validation", 10*time.Second)

	// 5. POST /validate.
	resp2 := authedPost(t, baseURL+"/api/v1/deployments/"+created.ID+"/validate", bearer,
		"application/json", "{}")
	if resp2.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp2.Body)
		_ = resp2.Body.Close()
		t.Fatalf("validate got %d: %s", resp2.StatusCode, b)
	}
	_ = resp2.Body.Close()

	// 6. The other 2 devices should now receive ApplyProfile commands.
	aCmd := readCommandWithin(t, devASub, 5*time.Second)
	bCmd := readCommandWithin(t, devBSub, 5*time.Second)
	if aCmd == nil || bCmd == nil {
		t.Fatal("rollout commands not received on dev-a / dev-b")
	}

	// 7. Publish success ACKs for both rollout devices.
	publishDeploymentResult(t, ctx, bus, devA, aCmd.GetCommandId(), created.ID, true, "")
	publishDeploymentResult(t, ctx, bus, devB, bCmd.GetCommandId(), created.ID, true, "")

	// 8. Wait for completed.
	waitForDeploymentStatus(t, baseURL, bearer, created.ID, "completed", 10*time.Second)

	// 9. Verify GET /{id} shows 3 results, all success.
	resp3 := authedGet(t, baseURL+"/api/v1/deployments/"+created.ID, bearer)
	var detail struct {
		Status  string `json:"status"`
		Results []struct {
			DeviceID string `json:"device_id"`
			Status   string `json:"status"`
			IsCanary bool   `json:"is_canary"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp3.Body).Decode(&detail); err != nil {
		_ = resp3.Body.Close()
		t.Fatal(err)
	}
	_ = resp3.Body.Close()
	if detail.Status != "completed" {
		t.Errorf("final status: got %s, want completed", detail.Status)
	}
	if len(detail.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(detail.Results))
	}
	for _, r := range detail.Results {
		if r.Status != "success" {
			t.Errorf("device %s status: got %s, want success", r.DeviceID, r.Status)
		}
	}
}

// --- helpers ---

// setupDeploymentE2EStack spins up postgres + nats containers, runs the
// schema migrations, wires the full api.Deps (including DeploymentsEngine
// and Deployments), starts the engine goroutine, starts the
// commandresultsingester, mounts the API on a free port, and returns
// everything callers need to drive the deployment flow over real HTTP+NATS.
//
// The returned cleanup tears down (in reverse): server, ingester, engine
// goroutine, NATS bus, pool, NATS container, postgres container.
func setupDeploymentE2EStack(t *testing.T, ctx context.Context) (
	*api.Deps,
	*auth.JWTSigner,
	uuid.UUID,
	string,
	*natsbus.Bus,
	func(),
) {
	t.Helper()

	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("lmdm"), postgres.WithUsername("lmdm"), postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}

	natsReq := testcontainers.ContainerRequest{
		Image: "nats:2.10-alpine", ExposedPorts: []string{"4222/tcp"},
		Cmd: []string{"-js"}, WaitingFor: wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	natsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: natsReq, Started: true,
	})
	if err != nil {
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	natsHost, _ := natsC.Host(ctx)
	natsPort, _ := natsC.MappedPort(ctx, "4222/tcp")
	natsURL := "nats://" + natsHost + ":" + natsPort.Port()

	bus, err := natsbus.Connect(ctx, natsURL)
	if err != nil {
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	if err := bus.EnsureStreams(ctx); err != nil {
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}

	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)
	keyPath := t.TempDir() + "/server.key"
	serverPriv, _, err := serverkey.LoadOrGenerate(keyPath)
	if err != nil {
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")

	profRepo := profilesRepo.NewRepository(pool, serverPriv)
	apiDeps, signer := newTestAPIDeps(t, pool, deviceRepo, tokenRepo, profRepo, bus.NC(), tenantID)

	// Wire the deployments engine + ingester just like main.go does.
	deploymentRepo := deployments.New(pool)
	deploymentEngine := deployments.NewEngine(deploymentRepo, bus.NC(), profRepo)
	apiDeps.Deployments = deploymentRepo
	apiDeps.DeploymentsEngine = deploymentEngine

	engineCtx, cancelEngine := context.WithCancel(context.Background())
	engineDone := make(chan struct{})
	go func() {
		defer close(engineDone)
		_ = deploymentEngine.Run(engineCtx)
	}()

	cmdResultsIng := commandresultsingester.New(bus, deviceRepo, deploymentEngine)
	if err := cmdResultsIng.Start(ctx); err != nil {
		cancelEngine()
		<-engineDone
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}

	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	mux := http.NewServeMux()
	mux.Handle("/api/", api.Router(apiDeps))
	srv, err := server.New(httpAddr, grpcAddr, mux, nil)
	if err != nil {
		cmdResultsIng.Stop()
		cancelEngine()
		<-engineDone
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	errs := srv.Start()
	select {
	case e := <-errs:
		_ = srv.Shutdown(2 * time.Second)
		cmdResultsIng.Stop()
		cancelEngine()
		<-engineDone
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatalf("server failed to start: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	baseURL := "http://" + httpAddr

	cleanup := func() {
		_ = srv.Shutdown(5 * time.Second)
		cmdResultsIng.Stop()
		cancelEngine()
		<-engineDone
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
	}

	return apiDeps, signer, tenantID, baseURL, bus, cleanup
}

// seedUserForDeploymentE2E inserts a single users row in the test tenant
// using raw SQL (bypasses bcrypt). The returned uuid is suitable as the JWT
// subject when minting an access token; the deployments handler records it
// as created_by_user_id and the FK requires a real row.
func seedUserForDeploymentE2E(t *testing.T, ctx context.Context, pool *db.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("seed user begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("seed user set_config: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, password_hash, role)
		VALUES ($1, $2, $3, 'unused-hash', 'admin')
	`, userID, tenantID, "e2e-"+userID.String()[:8]+"@test.local"); err != nil {
		t.Fatalf("seed user insert: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("seed user commit: %v", err)
	}
	return userID
}

// seedDeviceForDeploymentE2E inserts a workstation row via the devices repo.
func seedDeviceForDeploymentE2E(t *testing.T, ctx context.Context, pool *db.Pool, tenantID uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	repo := devices.NewRepository(pool)
	// Pubkey columns have a UNIQUE constraint, so derive both bytes from the
	// device id to keep every seeded device distinct.
	pubEd := []byte("ed-" + id.String())
	pubML := []byte("ml-" + id.String())
	if err := repo.Insert(ctx, &devices.Device{
		ID:                 id,
		TenantID:           tenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           hostname + "-" + id.String()[:8],
		AgentPubkeyEd25519: pubEd,
		AgentPubkeyMLDSA:   pubML,
	}); err != nil {
		t.Fatalf("seed device %s: %v", hostname, err)
	}
	return id
}

// seedProfileForDeploymentE2E inserts a minimal profile row directly via SQL.
// The engine only reads Version + YAMLContent + signatures to build the
// ApplyProfileCommand envelope; we don't need a properly signed profile here
// because the test never spins up a real agent that would verify it.
func seedProfileForDeploymentE2E(t *testing.T, ctx context.Context, pool *db.Pool, tenantID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	profileID := uuid.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("seed profile begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("seed profile set_config: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO profiles (id, tenant_id, name, version, yaml_content, json_content)
		VALUES ($1, $2, $3, '1.0.0',
		        'metadata:\n  name: e2e\n  version: 1.0.0\n',
		        '{}'::jsonb)
	`, profileID, tenantID, name+"-"+profileID.String()[:8]); err != nil {
		t.Fatalf("seed profile insert: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("seed profile commit: %v", err)
	}
	return profileID
}

// mintAccessTokenForUser issues an admin JWT whose subject matches a real
// users row. Used in place of testAccessToken so the deployments handler's
// FK on created_by_user_id is satisfied.
func mintAccessTokenForUser(t *testing.T, signer *auth.JWTSigner, userID, tenantID uuid.UUID) string {
	t.Helper()
	tok, err := signer.IssueAccess(userID, tenantID, auth.RoleAdmin, "e2e-deploy@test.local")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// mustSubscribeCommands installs a synchronous core-NATS subscription on the
// per-device commands subject. The deployments engine publishes via core
// NATS (bus.NC()), so a core subscriber observes the messages directly even
// though the COMMANDS JetStream stream also captures them.
func mustSubscribeCommands(t *testing.T, nc *nats.Conn, deviceID uuid.UUID) *nats.Subscription {
	t.Helper()
	sub, err := nc.SubscribeSync("fleet.agent." + deviceID.String() + ".commands")
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return sub
}

// readCommandWithin pulls one CommandEnvelope off sub or returns nil on
// timeout. Errors other than nats.ErrTimeout fail the test.
func readCommandWithin(t *testing.T, sub *nats.Subscription, d time.Duration) *lmdmv1.CommandEnvelope {
	t.Helper()
	msg, err := sub.NextMsg(d)
	if err != nil {
		if errors.Is(err, nats.ErrTimeout) {
			return nil
		}
		t.Fatal(err)
	}
	var env lmdmv1.CommandEnvelope
	if err := proto.Unmarshal(msg.Data, &env); err != nil {
		t.Fatal(err)
	}
	return &env
}

// publishDeploymentResult sends a CommandResult through JetStream so the
// commandresultsingester (which consumes from the COMMAND_RESULTS durable
// consumer) actually picks it up. Publishing via core NATS would still hit
// the stream but going through the JS client makes the at-least-once
// semantics explicit and matches what a real agent does.
func publishDeploymentResult(
	t *testing.T,
	ctx context.Context,
	bus *natsbus.Bus,
	deviceID uuid.UUID,
	commandID, deploymentID string,
	success bool,
	errMsg string,
) {
	t.Helper()
	result := &lmdmv1.CommandResult{
		CommandId:    commandID,
		DeviceId:     &lmdmv1.DeviceID{Id: deviceID.String()},
		Timestamp:    timestamppb.Now(),
		Success:      success,
		Error:        errMsg,
		SnapshotId:   deploymentID,
		DeploymentId: &lmdmv1.DeploymentID{Id: deploymentID},
	}
	data, err := proto.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	subject := "fleet.agent." + deviceID.String() + ".command-result"
	if _, err := bus.JetStream().Publish(ctx, subject, data); err != nil {
		t.Fatalf("publish ack: %v", err)
	}
}

// waitForDeploymentStatus polls GET /deployments/{id} until the JSON status
// field equals want, or fails the test on timeout. 200ms cadence keeps test
// runtime short while still letting the engine + ingester catch up.
func waitForDeploymentStatus(t *testing.T, baseURL, bearer, id, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		resp := authedGet(t, baseURL+"/api/v1/deployments/"+id, bearer)
		var d struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&d)
		_ = resp.Body.Close()
		last = d.Status
		if d.Status == want {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("deployment %s did not reach %s within %s (last=%s)", id, want, timeout, last)
}

// marshalJSONForE2E is a thin t.Fatal-on-error wrapper around json.Marshal
// so callers don't have to repeat the err-check boilerplate.
func marshalJSONForE2E(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
