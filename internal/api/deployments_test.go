// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/deployments"
	"github.com/cto-externe/lmdm/internal/profiles"
)

const deploymentsTestTenant = "00000000-0000-0000-0000-000000000000"

// fakeBus is a test double for deployments.CommandPublisher. It records every
// Publish call; the integration test asserts the canary subject appears after
// a successful create.
type fakeBus struct {
	mu   sync.Mutex
	msgs []fakeBusMsg
}

type fakeBusMsg struct {
	Subject string
	Data    []byte
}

func (f *fakeBus) Publish(subject string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, fakeBusMsg{Subject: subject, Data: data})
	return nil
}

func (f *fakeBus) subjects() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.msgs))
	for _, m := range f.msgs {
		out = append(out, m.Subject)
	}
	return out
}

// fakeProfileLoader returns a minimal profile row. The engine only uses
// Version / YAMLContent / SignatureEd25519 / SignatureMLDSA to build the
// ApplyProfileCommand envelope, so zero-valued / empty fields are fine for
// the API test — we're not exercising the agent-side unmarshal here.
type fakeProfileLoader struct{}

func (f *fakeProfileLoader) FindByID(_ context.Context, _, id uuid.UUID) (*profiles.Profile, error) {
	return &profiles.Profile{
		ID:          id,
		Version:     "1.0.0",
		YAMLContent: "metadata:\n  name: test\n  version: 1.0.0\n",
	}, nil
}

// setupDeploymentsDeps spins up Postgres + migrations, wires a Deps with a
// real deployments.Repository, and starts a deployments.Engine backed by a
// fakeBus/fakeProfileLoader. Engine.Run is launched on a background goroutine
// and cancelled by cleanup.
func setupDeploymentsDeps(t *testing.T) (*Deps, *fakeBus, func()) {
	t.Helper()
	ctx, cancelTimeout := context.WithTimeout(context.Background(), 60*time.Second)

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

	repo := deployments.New(pool)
	bus := &fakeBus{}
	loader := &fakeProfileLoader{}

	engine := deployments.NewEngine(repo, bus, loader)
	runCtx, cancelRun := context.WithCancel(context.Background())
	engineDone := make(chan struct{})
	go func() {
		defer close(engineDone)
		_ = engine.Run(runCtx)
	}()

	cleanup := func() {
		cancelRun()
		<-engineDone
		pool.Close()
		_ = pg.Terminate(ctx)
		cancelTimeout()
	}

	deps := &Deps{
		Pool:              pool,
		Deployments:       repo,
		DeploymentsEngine: engine,
		TenantID:          uuid.MustParse(deploymentsTestTenant),
	}
	return deps, bus, cleanup
}

// seedDeploymentFixtures inserts one profile, two devices, and one user row
// under the test tenant via raw SQL (bypasses the profiles signing path and
// the users hashing path — neither is needed for the API surface). Returns
// (profileID, canaryDeviceID, targetDeviceID, userID).
func seedDeploymentFixtures(t *testing.T, ctx context.Context, pool *db.Pool, tenantID uuid.UUID) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	profileID := uuid.New()
	canaryID := uuid.New()
	targetID := uuid.New()
	userID := uuid.New()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("seed begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("seed set_config: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO profiles (id, tenant_id, name, yaml_content, json_content)
		VALUES ($1, $2, $3, '{}', '{}'::jsonb)
	`, profileID, tenantID, "test-profile-"+profileID.String()[:8]); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname)
		VALUES ($1, $2, 'workstation', $3)
	`, canaryID, tenantID, "canary-"+canaryID.String()[:8]); err != nil {
		t.Fatalf("seed canary device: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname)
		VALUES ($1, $2, 'workstation', $3)
	`, targetID, tenantID, "target-"+targetID.String()[:8]); err != nil {
		t.Fatalf("seed target device: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, password_hash, role)
		VALUES ($1, $2, $3, 'unused-hash', 'operator')
	`, userID, tenantID, "op-"+userID.String()[:8]+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	return profileID, canaryID, targetID, userID
}

// requestWithPrincipal builds an httptest.NewRequest with a Principal already
// stored on the context — the test bypasses the RequireAuth middleware and
// calls the handler directly. userID must correspond to a seeded users row
// because handleCreateDeployment records it as created_by_user_id and the FK
// is enforced at insert time.
func requestWithPrincipal(method, target string, body []byte, tenantID, userID uuid.UUID) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	p := &auth.Principal{
		UserID:   userID,
		TenantID: tenantID,
		Role:     auth.RoleOperator,
		Email:    "op@test.local",
	}
	return r.WithContext(auth.WithPrincipal(r.Context(), p))
}

// TestIntegrationDeploymentsAPI_CRUD drives the five /deployments endpoints
// end-to-end against a real Postgres + an engine backed by fakes. It does NOT
// exercise the JWT middleware (the e2e suite owns that); here we inject a
// Principal directly into the request context to reach the handler body.
func TestIntegrationDeploymentsAPI_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	deps, bus, cleanup := setupDeploymentsDeps(t)
	defer cleanup()

	ctx := context.Background()
	profileID, canaryID, targetID, userID := seedDeploymentFixtures(t, ctx, deps.Pool, deps.TenantID)

	// 1. POST /deployments — 201 + status=canary_running (engine publishes the
	// canary ApplyProfileCommand synchronously and flips the row).
	createBody, _ := json.Marshal(createDeploymentReq{
		ProfileID:           profileID.String(),
		TargetDeviceIDs:     []string{canaryID.String(), targetID.String()},
		CanaryDeviceID:      canaryID.String(),
		ValidationMode:      "manual",
		ValidationTimeoutS:  1800,
		FailureThresholdPct: 10,
	})
	rec := httptest.NewRecorder()
	req := requestWithPrincipal("POST", "/api/v1/deployments", createBody, deps.TenantID, userID)
	deps.handleCreateDeployment(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /deployments status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var created deploymentJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v; body=%s", err, rec.Body.String())
	}
	if created.ID == uuid.Nil {
		t.Fatal("created.ID is nil")
	}
	if created.Status != string(deployments.StatusCanaryRunning) {
		t.Errorf("Status = %q, want %q", created.Status, deployments.StatusCanaryRunning)
	}
	// The fake bus should have received exactly one canary publish.
	subjects := bus.subjects()
	wantSubject := "fleet.agent." + canaryID.String() + ".commands"
	found := false
	for _, s := range subjects {
		if s == wantSubject {
			found = true
		}
	}
	if !found {
		t.Errorf("bus subjects = %v, want one of them = %q", subjects, wantSubject)
	}

	// 2. GET /deployments — expect at least one row including ours.
	rec = httptest.NewRecorder()
	req = requestWithPrincipal("GET", "/api/v1/deployments", nil, deps.TenantID, userID)
	deps.handleListDeployments(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /deployments status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var listBody struct {
		Data  []deploymentJSON `json:"data"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode list response: %v; body=%s", err, rec.Body.String())
	}
	if listBody.Total < 1 {
		t.Errorf("list.Total = %d, want >= 1", listBody.Total)
	}
	foundCreated := false
	for _, d := range listBody.Data {
		if d.ID == created.ID {
			foundCreated = true
		}
	}
	if !foundCreated {
		t.Errorf("list did not include created deployment %s", created.ID)
	}

	// 3. GET /deployments/{id} — deployment + 1 result (canary, status=applying).
	rec = httptest.NewRecorder()
	req = requestWithPrincipal("GET", "/api/v1/deployments/"+created.ID.String(), nil, deps.TenantID, userID)
	req.SetPathValue("id", created.ID.String())
	deps.handleGetDeployment(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /deployments/{id} status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var detail deploymentWithResults
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail response: %v; body=%s", err, rec.Body.String())
	}
	if detail.ID != created.ID {
		t.Errorf("detail.ID = %s, want %s", detail.ID, created.ID)
	}
	if len(detail.Results) != 1 {
		t.Fatalf("detail.Results len = %d, want 1 (canary applying)", len(detail.Results))
	}
	if detail.Results[0].DeviceID != canaryID {
		t.Errorf("results[0].DeviceID = %s, want canary %s", detail.Results[0].DeviceID, canaryID)
	}
	if !detail.Results[0].IsCanary {
		t.Error("results[0].IsCanary = false, want true")
	}
	if detail.Results[0].Status != string(deployments.ResultApplying) {
		t.Errorf("results[0].Status = %q, want %q", detail.Results[0].Status, deployments.ResultApplying)
	}

	// 4. POST /deployments/{id}/validate — 202.
	rec = httptest.NewRecorder()
	req = requestWithPrincipal("POST", "/api/v1/deployments/"+created.ID.String()+"/validate", nil, deps.TenantID, userID)
	req.SetPathValue("id", created.ID.String())
	deps.handleValidateDeployment(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /validate status = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}

	// 5. POST /deployments/{id}/rollback — 202 with a reason in the body.
	rollbackBody, _ := json.Marshal(rollbackReq{Reason: "manual rollback for test"})
	rec = httptest.NewRecorder()
	req = requestWithPrincipal("POST", "/api/v1/deployments/"+created.ID.String()+"/rollback", rollbackBody, deps.TenantID, userID)
	req.SetPathValue("id", created.ID.String())
	deps.handleRollbackDeployment(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /rollback status = %d, want 202; body=%s", rec.Code, rec.Body.String())
	}
}
