// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
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

	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
)

const healthTestTenant = "00000000-0000-0000-0000-000000000000"

func setupHealthDeps(t *testing.T) (*Deps, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	pg, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("lmdm"),
		postgres.WithUsername("lmdm"),
		postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancel()
	}
	deps := &Deps{
		Pool:     pool,
		Devices:  devices.NewRepository(pool),
		TenantID: uuid.MustParse(healthTestTenant),
	}
	return deps, cleanup
}

func seedHealthDevice(t *testing.T, deps *Deps, suffix string) uuid.UUID {
	t.Helper()
	d := &devices.Device{
		ID:                 uuid.New(),
		TenantID:           deps.TenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           "PC-API-HEALTH-" + suffix,
		AgentPubkeyEd25519: []byte("ed-api-" + suffix),
		AgentPubkeyMLDSA:   []byte("ml-api-" + suffix),
	}
	if err := deps.Devices.Insert(context.Background(), d); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return d.ID
}

// TestIntegrationHandleGetHealth groups the success, 404, and 400 cases under
// a single testcontainers Postgres spin-up to keep CI fast. The real RBAC and
// auth wrapper is exercised by the e2e suite (Task 16); here we call the
// handler directly to validate the JSON shape and error mapping.
func TestIntegrationHandleGetHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	deps, cleanup := setupHealthDeps(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("ReturnsSnapshot", func(t *testing.T) {
		deviceID := seedHealthDevice(t, deps, "ok")
		snapJSON := []byte(`{"deviceId":{"id":"` + deviceID.String() + `"},"overallScore":"HEALTH_SCORE_GREEN"}`)
		summary := devices.HealthSummary{OverallScore: 0}
		if err := deps.Devices.UpsertHealthSnapshot(ctx, deps.TenantID, deviceID, summary, snapJSON); err != nil {
			t.Fatalf("UpsertHealthSnapshot: %v", err)
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/devices/"+deviceID.String()+"/health", nil)
		req.SetPathValue("id", deviceID.String())
		deps.handleGetHealth(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type: got %q, want application/json", got)
		}

		var body struct {
			ObservedAt string          `json:"observed_at"`
			Snapshot   json.RawMessage `json:"snapshot"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
		}
		if body.ObservedAt == "" {
			t.Error("observed_at is empty")
		}
		if _, err := time.Parse(time.RFC3339, body.ObservedAt); err != nil {
			t.Errorf("observed_at not RFC3339: %v", err)
		}
		var snap map[string]any
		if err := json.Unmarshal(body.Snapshot, &snap); err != nil {
			t.Fatalf("snapshot is not valid JSON: %v", err)
		}
		if snap["overallScore"] != "HEALTH_SCORE_GREEN" {
			t.Errorf("snapshot.overallScore = %v, want HEALTH_SCORE_GREEN", snap["overallScore"])
		}
		if _, ok := snap["deviceId"]; !ok {
			t.Error("snapshot missing deviceId")
		}
	})

	t.Run("NotFound_When_NoSnapshot", func(t *testing.T) {
		deviceID := seedHealthDevice(t, deps, "nosnap")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/devices/"+deviceID.String()+"/health", nil)
		req.SetPathValue("id", deviceID.String())
		deps.handleGetHealth(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status: got %d, want 404; body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode error response: %v", err)
		}
		if body["error"] != "no health snapshot" {
			t.Errorf("error message: got %v, want \"no health snapshot\"", body["error"])
		}
	})

	t.Run("InvalidUUID", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/devices/not-a-uuid/health", nil)
		req.SetPathValue("id", "not-a-uuid")
		deps.handleGetHealth(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status: got %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
	})
}
