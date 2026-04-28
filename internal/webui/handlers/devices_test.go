// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/webui/csrf"
	"github.com/cto-externe/lmdm/internal/webui/i18n"
)

const devTestTenant = "00000000-0000-0000-0000-000000000000"

// setupDevicesRepo spins up a Postgres testcontainer and returns a Repository and cleanup func.
func setupDevicesRepo(t *testing.T) (*devices.Repository, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)

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
	return devices.NewRepository(pool), cleanup
}

// seedDevice inserts a device under tenantID.
func seedDevice(t *testing.T, r *devices.Repository, tenantID uuid.UUID, hostname string, status devices.Status, idx int) uuid.UUID {
	t.Helper()
	d := &devices.Device{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           hostname,
		Status:             status,
		AgentPubkeyEd25519: []byte(fmt.Sprintf("ed25519-%d", idx)),
		AgentPubkeyMLDSA:   []byte(fmt.Sprintf("mldsa-%d", idx)),
	}
	if err := r.Insert(context.Background(), d); err != nil {
		t.Fatalf("seedDevice %s: %v", hostname, err)
	}
	return d.ID
}

// newDevicesDeps returns a DevicesDeps wired for tests.
func newDevicesDeps(repo *devices.Repository) *DevicesDeps {
	_ = i18n.Load()
	return &DevicesDeps{
		Repo: repo,
		CSRF: csrf.New([]byte("test-key-32-bytes-padding-xxxxxX")),
	}
}

// reqCtxPrincipal returns a recorder and a request whose context carries a Principal.
func reqCtxPrincipal(method, target string, tenantID uuid.UUID) (*httptest.ResponseRecorder, *http.Request) {
	_ = i18n.Load()
	req := httptest.NewRequest(method, target, nil)
	p := &auth.Principal{
		UserID:   uuid.New(),
		TenantID: tenantID,
		Role:     auth.RoleAdmin,
		Email:    "test@example.com",
	}
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	return httptest.NewRecorder(), req
}

func TestIntegrationDevicesList_RendersTable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	repo, cleanup := setupDevicesRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(devTestTenant)
	seedDevice(t, repo, tenantID, "HOST-A", devices.StatusOnline, 1)
	seedDevice(t, repo, tenantID, "HOST-B", devices.StatusOffline, 2)

	deps := newDevicesDeps(repo)
	rr, req := reqCtxPrincipal("GET", "/web/devices", tenantID)
	deps.HandleList(rr, req)

	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("status %d, body: %s", rr.Code, body)
	}
	if !strings.Contains(body, "HOST-A") {
		t.Error("response missing HOST-A")
	}
	if !strings.Contains(body, "HOST-B") {
		t.Error("response missing HOST-B")
	}
	if !strings.Contains(body, "<table") {
		t.Error("response missing <table element")
	}
}

func TestIntegrationDevicesFragment_FilterByStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	repo, cleanup := setupDevicesRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(devTestTenant)
	seedDevice(t, repo, tenantID, "ONLINE-1", devices.StatusOnline, 1)
	seedDevice(t, repo, tenantID, "ONLINE-2", devices.StatusOnline, 2)
	seedDevice(t, repo, tenantID, "OFFLINE-1", devices.StatusOffline, 3)

	deps := newDevicesDeps(repo)
	rr, req := reqCtxPrincipal("GET", "/web/devices/fragment?status=online", tenantID)
	deps.HandleFragment(rr, req)

	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("status %d, body: %s", rr.Code, body)
	}
	if !strings.Contains(body, "ONLINE-1") {
		t.Error("response missing ONLINE-1")
	}
	if !strings.Contains(body, "ONLINE-2") {
		t.Error("response missing ONLINE-2")
	}
	if strings.Contains(body, "OFFLINE-1") {
		t.Error("response must not contain OFFLINE-1 when filtering by status=online")
	}
}

func TestIntegrationDevicesFragment_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	repo, cleanup := setupDevicesRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(devTestTenant)
	for i := 0; i < 5; i++ {
		seedDevice(t, repo, tenantID, fmt.Sprintf("PAG-HOST-%03d", i), devices.StatusOnline, i)
	}

	deps := newDevicesDeps(repo)

	// Page 1: 2 devices.
	rr1, req1 := reqCtxPrincipal("GET", "/web/devices/fragment?page_size=2&page=1", tenantID)
	deps.HandleFragment(rr1, req1)
	if rr1.Code != 200 {
		t.Fatalf("page1 status %d", rr1.Code)
	}
	body1 := rr1.Body.String()

	// Page 2: 2 different devices.
	rr2, req2 := reqCtxPrincipal("GET", "/web/devices/fragment?page_size=2&page=2", tenantID)
	deps.HandleFragment(rr2, req2)
	if rr2.Code != 200 {
		t.Fatalf("page2 status %d", rr2.Code)
	}
	body2 := rr2.Body.String()

	// Page 3: 1 device.
	rr3, req3 := reqCtxPrincipal("GET", "/web/devices/fragment?page_size=2&page=3", tenantID)
	deps.HandleFragment(rr3, req3)
	if rr3.Code != 200 {
		t.Fatalf("page3 status %d", rr3.Code)
	}
	body3 := rr3.Body.String()

	// Count hostnames on each page.
	count1 := strings.Count(body1, "PAG-HOST-")
	count2 := strings.Count(body2, "PAG-HOST-")
	count3 := strings.Count(body3, "PAG-HOST-")

	if count1 != 2 {
		t.Errorf("page1: got %d PAG-HOST entries, want 2", count1)
	}
	if count2 != 2 {
		t.Errorf("page2: got %d PAG-HOST entries, want 2", count2)
	}
	if count3 != 1 {
		t.Errorf("page3: got %d PAG-HOST entries, want 1", count3)
	}

	// No overlap between page1 and page2.
	for i := 0; i < 5; i++ {
		h := fmt.Sprintf("PAG-HOST-%03d", i)
		if strings.Contains(body1, h) && strings.Contains(body2, h) {
			t.Errorf("hostname %s appears on both page1 and page2", h)
		}
	}
}
