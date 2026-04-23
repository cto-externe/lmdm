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
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/patchschedule"
)

// patchTestTenant uses the pre-seeded default tenant so RLS (lmdm_current_tenant()
// defaults to 00000000-0000-0000-0000-000000000000 when the GUC is not set)
// does not filter out rows inserted during handler calls.
const patchTestTenant = "00000000-0000-0000-0000-000000000000"

// patchTestSetup holds shared state for a single test run.
type patchTestSetup struct {
	deps   *Deps
	userID uuid.UUID
}

func setupPatchDeps(t *testing.T) (*patchTestSetup, func()) {
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

	// Seed a user row so the created_by_user_id FK is satisfied.
	tenantID := uuid.MustParse(patchTestTenant)
	userID := uuid.New()
	seedCtx := context.Background()
	tx, txErr := pool.Begin(seedCtx)
	if txErr != nil {
		_ = pg.Terminate(ctx)
		cancelTimeout()
		t.Fatalf("seed begin: %v", txErr)
	}
	if _, execErr := tx.Exec(seedCtx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); execErr != nil {
		_ = tx.Rollback(seedCtx)
		_ = pg.Terminate(ctx)
		cancelTimeout()
		t.Fatalf("seed set_config: %v", execErr)
	}
	if _, execErr := tx.Exec(seedCtx,
		`INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES ($1, $2, $3, 'unused-hash', 'operator')`,
		userID, tenantID, "patch-test-"+userID.String()[:8]+"@test.local",
	); execErr != nil {
		_ = tx.Rollback(seedCtx)
		_ = pg.Terminate(ctx)
		cancelTimeout()
		t.Fatalf("seed user: %v", execErr)
	}
	if commitErr := tx.Commit(seedCtx); commitErr != nil {
		_ = pg.Terminate(ctx)
		cancelTimeout()
		t.Fatalf("seed commit: %v", commitErr)
	}

	cleanup := func() {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancelTimeout()
	}

	deps := &Deps{
		Pool:      pool,
		PatchRepo: patchschedule.NewRepository(pool),
		TenantID:  tenantID,
	}
	return &patchTestSetup{deps: deps, userID: userID}, cleanup
}

// patchReqWithUser builds a request with a Principal whose UserID is the seeded user.
func patchReqWithUser(method, target string, body []byte, tenantID, userID uuid.UUID) *http.Request {
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

func TestIntegrationCreatePatchSchedule_ValidCron_Returns201(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupPatchDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	body, _ := json.Marshal(createPatchScheduleRequest{
		CronExpr:           "0 2 * * *",
		FilterSecurityOnly: true,
	})
	rec := httptest.NewRecorder()
	req := patchReqWithUser("POST", "/api/v1/patch-schedules", body, d.TenantID, userID)
	d.handleCreatePatchSchedule(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var got patchScheduleJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if got.ID == uuid.Nil {
		t.Error("response ID is nil")
	}
	if got.CronExpr != "0 2 * * *" {
		t.Errorf("CronExpr = %q, want %q", got.CronExpr, "0 2 * * *")
	}
	if !got.FilterSecurityOnly {
		t.Error("FilterSecurityOnly = false, want true")
	}
	if got.NextFireAt.IsZero() {
		t.Error("NextFireAt is zero")
	}
}

func TestIntegrationCreatePatchSchedule_InvalidCron_Returns400(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupPatchDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	body, _ := json.Marshal(createPatchScheduleRequest{CronExpr: "not-a-cron"})
	rec := httptest.NewRecorder()
	req := patchReqWithUser("POST", "/api/v1/patch-schedules", body, d.TenantID, userID)
	d.handleCreatePatchSchedule(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationCreatePatchSchedule_MissingCron_Returns400(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupPatchDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	body, _ := json.Marshal(createPatchScheduleRequest{CronExpr: ""})
	rec := httptest.NewRecorder()
	req := patchReqWithUser("POST", "/api/v1/patch-schedules", body, d.TenantID, userID)
	d.handleCreatePatchSchedule(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationListPatchSchedules_ReturnsAll(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupPatchDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	// Create two schedules.
	for _, expr := range []string{"0 1 * * *", "0 3 * * 1"} {
		body, _ := json.Marshal(createPatchScheduleRequest{CronExpr: expr})
		rec := httptest.NewRecorder()
		req := patchReqWithUser("POST", "/api/v1/patch-schedules", body, d.TenantID, userID)
		d.handleCreatePatchSchedule(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("seed create status = %d; body=%s", rec.Code, rec.Body.String())
		}
	}

	// List.
	rec := httptest.NewRecorder()
	req := patchReqWithUser("GET", "/api/v1/patch-schedules", nil, d.TenantID, userID)
	d.handleListPatchSchedules(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var listBody struct {
		Data  []patchScheduleJSON `json:"data"`
		Total int                 `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode list: %v; body=%s", err, rec.Body.String())
	}
	if listBody.Total != 2 {
		t.Errorf("total = %d, want 2", listBody.Total)
	}
	if len(listBody.Data) != 2 {
		t.Errorf("len(data) = %d, want 2", len(listBody.Data))
	}
}

func TestIntegrationGetPatchSchedule_NotFound_Returns404(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupPatchDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	randomID := uuid.New()
	rec := httptest.NewRecorder()
	req := patchReqWithUser("GET", "/api/v1/patch-schedules/"+randomID.String(), nil, d.TenantID, userID)
	req.SetPathValue("id", randomID.String())
	d.handleGetPatchSchedule(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationDeletePatchSchedule_Existing_Returns204(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	setup, cleanup := setupPatchDeps(t)
	defer cleanup()
	d, userID := setup.deps, setup.userID

	// Create a schedule.
	createBody, _ := json.Marshal(createPatchScheduleRequest{CronExpr: "30 4 * * *"})
	createRec := httptest.NewRecorder()
	createReq := patchReqWithUser("POST", "/api/v1/patch-schedules", createBody, d.TenantID, userID)
	d.handleCreatePatchSchedule(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%s", createRec.Code, createRec.Body.String())
	}
	var created patchScheduleJSON
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Delete it.
	delRec := httptest.NewRecorder()
	delReq := patchReqWithUser("DELETE", "/api/v1/patch-schedules/"+created.ID.String(), nil, d.TenantID, userID)
	delReq.SetPathValue("id", created.ID.String())
	d.handleDeletePatchSchedule(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204; body=%s", delRec.Code, delRec.Body.String())
	}

	// Subsequent GET must return 404.
	getRec := httptest.NewRecorder()
	getReq := patchReqWithUser("GET", "/api/v1/patch-schedules/"+created.ID.String(), nil, d.TenantID, userID)
	getReq.SetPathValue("id", created.ID.String())
	d.handleGetPatchSchedule(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete status = %d, want 404; body=%s", getRec.Code, getRec.Body.String())
	}
}
