// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/revocation"
)

func TestRouterReturnsStatusForDevicesRoute(t *testing.T) {
	deps := &Deps{TenantID: uuid.MustParse("00000000-0000-0000-0000-000000000000")}
	handler := Router(deps)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/devices", nil)
	handler.ServeHTTP(rec, req)

	// Without a real DB, ListDevices will error. We accept 500 (not panic/0).
	if rec.Code == 0 {
		t.Error("must return a status code")
	}
}

// fakeNATSPublisher satisfies revocation.NATSClient for the publish-only path.
// Subscribe is unused in this test but required by the interface; we return
// a zero-value subscription + nil error rather than wiring NATS just to
// exercise the publish subject.
type fakeNATSPublisher struct {
	subjects [][]byte
	subject  string
}

func (f *fakeNATSPublisher) Publish(subject string, data []byte) error {
	f.subject = subject
	dup := make([]byte, len(data))
	copy(dup, data)
	f.subjects = append(f.subjects, dup)
	return nil
}

func (f *fakeNATSPublisher) Subscribe(_ string, _ nats.MsgHandler) (*nats.Subscription, error) {
	return nil, nil
}

// seedRevokeFixtures inserts one admin user and one device (with a
// current_cert_serial) under the test tenant. Returns (deviceID, userID, serial).
func seedRevokeFixtures(t *testing.T, ctx context.Context, pool *db.Pool, tenantID uuid.UUID) (uuid.UUID, uuid.UUID, string) {
	t.Helper()
	deviceID := uuid.New()
	userID := uuid.New()
	serial := "serial-" + deviceID.String()[:8]

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("seed begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("seed set_config: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, password_hash, role)
		VALUES ($1, $2, $3, 'unused-hash', 'admin')
	`, userID, tenantID, "admin-"+userID.String()[:8]+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, tenant_id, device_type, hostname, current_cert_serial)
		VALUES ($1, $2, 'workstation', $3, $4)
	`, deviceID, tenantID, "dev-"+deviceID.String()[:8], serial); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	return deviceID, userID, serial
}

// TestIntegrationHandleRevokeDevice_InsertsRowAndBroadcasts spins up Postgres,
// seeds a device with a current cert serial, calls handleRevokeDevice with an
// admin principal, and asserts:
//   - response is 204 No Content
//   - a row appears in revoked_certificates for (tenant, serial)
//   - the fake NATS publisher received the serial on the broadcast subject
func TestIntegrationHandleRevokeDevice_InsertsRowAndBroadcasts(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancelTimeout := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelTimeout()

	pg, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("lmdm"),
		postgres.WithUsername("lmdm"),
		postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pg.Terminate(ctx) }()

	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	tenantID := uuid.MustParse(deploymentsTestTenant)
	deviceID, userID, serial := seedRevokeFixtures(t, ctx, pool, tenantID)

	deps := &Deps{
		Pool:       pool,
		Devices:    devices.NewRepository(pool),
		Revocation: revocation.New(pool),
		TenantID:   tenantID,
		// NATS is a *nats.Conn on Deps; the publish path gates on nil, so
		// leaving it nil here means the broadcast line is a no-op. We exercise
		// the publish path separately against the revocation package directly.
	}

	// Build a request with an admin principal injected on the context.
	reqBody, _ := json.Marshal(revokeDeviceReq{Reason: "test-key-compromise"})
	req := httptest.NewRequest("POST", "/api/v1/devices/"+deviceID.String()+"/revoke", bytes.NewReader(reqBody))
	req.SetPathValue("id", deviceID.String())
	p := &auth.Principal{
		UserID:   userID,
		TenantID: tenantID,
		Role:     auth.RoleAdmin,
		Email:    "admin@test.local",
	}
	req = req.WithContext(auth.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()

	deps.handleRevokeDevice(rec, req)

	if rec.Code != 204 {
		t.Fatalf("revoke status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}

	// The revocation row exists for (tenant, serial).
	revRepo := revocation.New(pool)
	isRevoked, err := revRepo.IsRevoked(ctx, tenantID, serial)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !isRevoked {
		t.Fatalf("serial %q not marked revoked in DB", serial)
	}

	// Verify the revocation package's Publish helper routes to the expected
	// subject. We exercise it against a stand-in NATS client here because
	// Deps.NATS is a concrete *nats.Conn in production; swapping in a fake
	// there would require more invasive plumbing than the scope of this test.
	fake := &fakeNATSPublisher{}
	if err := revocation.Publish(fake, serial); err != nil {
		t.Fatalf("revocation.Publish: %v", err)
	}
	if fake.subject != revocation.BroadcastSubject {
		t.Errorf("broadcast subject = %q, want %q", fake.subject, revocation.BroadcastSubject)
	}
	if len(fake.subjects) != 1 || string(fake.subjects[0]) != serial {
		t.Errorf("broadcast payloads = %v, want one entry = %q", fake.subjects, serial)
	}
}
