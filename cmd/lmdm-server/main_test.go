// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agentbus"
	"github.com/cto-externe/lmdm/internal/agentenroll"
	"github.com/cto-externe/lmdm/internal/agentinventoryrunner"
	"github.com/cto-externe/lmdm/internal/agentrunner"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/inventoryingester"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/grpcservices"
	"github.com/cto-externe/lmdm/internal/natsbus"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
	"github.com/cto-externe/lmdm/internal/server"
	"github.com/cto-externe/lmdm/internal/serverkey"
	"github.com/cto-externe/lmdm/internal/statusingester"
	"github.com/cto-externe/lmdm/internal/tokens"
)

func TestIntegrationHealthzReportsAllGreen(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

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
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}

	natsReq := testcontainers.ContainerRequest{
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		Cmd:          []string{"-js"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	natsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: natsReq,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = natsC.Terminate(ctx) })
	natsHost, _ := natsC.Host(ctx)
	natsPort, _ := natsC.MappedPort(ctx, "4222/tcp")
	natsURL := "nats://" + natsHost + ":" + natsPort.Port()

	if err := db.MigrateUp(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	bus, err := natsbus.Connect(ctx, natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}

	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)

	// S3 check is omitted from this test — we don't run Garage in the e2e.
	// Task 20 covers the manual smoke test including Garage.
	mux := http.NewServeMux()
	mux.Handle("/healthz", server.NewHealthHandler(map[string]server.HealthChecker{
		"db": server.HealthCheckerFunc(func(ctx context.Context) error { return pool.Ping(ctx) }),
		"nats": server.HealthCheckerFunc(func(ctx context.Context) error {
			_, err := bus.ListStreamNames(ctx)
			return err
		}),
	}))

	srv, err := server.New(httpAddr, grpcAddr, mux)
	if err != nil {
		t.Fatal(err)
	}
	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()

	// Wait until /healthz is reachable.
	url := "http://" + httpAddr + "/healthz"
	deadline := time.Now().Add(10 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get(url) //nolint:gosec // test-controlled URL pointing at the freshly-started in-process server
		if err == nil {
			break
		}
		select {
		case e := <-errs:
			t.Fatalf("server exited early: %v", e)
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	if resp == nil {
		t.Fatal("healthz never came up")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var payload struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status != "ok" {
		t.Errorf("status = %q, checks = %+v", payload.Status, payload.Checks)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func TestIntegrationEnrollEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Bring up postgres + nats.
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
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")

	natsReq := testcontainers.ContainerRequest{
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		Cmd:          []string{"-js"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
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

	// Bootstrap server resources.
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	bus, err := natsbus.Connect(ctx, natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}

	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)
	keyPath := t.TempDir() + "/server.key"
	serverPriv, serverPub, err := serverkey.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Create a token for the test.
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	plaintext, _, err := tokenRepo.Create(ctx, tokens.CreateRequest{
		TenantID:    tenantID,
		Description: "e2e enroll",
		MaxUses:     1,
		TTL:         time.Hour,
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build server with EnrollmentService registered.
	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	srv, err := server.New(httpAddr, grpcAddr, http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}
	endpoints := &lmdmv1.ServerEndpoints{NatsUrl: natsURL, GrpcUrl: grpcAddr, ApiUrl: "http://" + httpAddr}
	svc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour)
	lmdmv1.RegisterEnrollmentServiceServer(srv.GRPC(), svc)

	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()
	select {
	case e := <-errs:
		t.Fatalf("server failed: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	// Agent client.
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, agentPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	resp, err := lmdmv1.NewEnrollmentServiceClient(conn).Enroll(ctx, &lmdmv1.EnrollRequest{
		EnrollmentToken: plaintext,
		AgentPublicKey:  &lmdmv1.HybridPublicKey{Ed25519: agentPub.Ed25519, MlDsa: agentPub.MLDSA},
		Hardware:        &lmdmv1.HardwareFingerprint{Hostname: "PC-E2E"},
		AgentVersion:    "0.1.0",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if resp.GetDeviceId().GetId() == "" {
		t.Fatal("device_id missing")
	}
	if len(resp.GetAgentCertificate()) == 0 {
		t.Fatal("certificate missing")
	}
}

func TestIntegrationHeartbeatLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

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
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		Cmd:          []string{"-js"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
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

	bus, err := natsbus.Connect(ctx, natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}

	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)
	keyPath := t.TempDir() + "/server.key"
	serverPriv, serverPub, err := serverkey.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	plaintext, _, err := tokenRepo.Create(ctx, tokens.CreateRequest{
		TenantID:    tenantID,
		Description: "e2e hb",
		MaxUses:     1,
		TTL:         time.Hour,
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	srv, err := server.New(httpAddr, grpcAddr, http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}
	endpoints := &lmdmv1.ServerEndpoints{NatsUrl: natsURL, GrpcUrl: grpcAddr, ApiUrl: "http://" + httpAddr}
	enrollSvc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour)
	lmdmv1.RegisterEnrollmentServiceServer(srv.GRPC(), enrollSvc)

	ingester := statusingester.New(bus, deviceRepo)
	if err := ingester.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer ingester.Stop()

	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()
	select {
	case e := <-errs:
		t.Fatalf("server failed: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	_, agentPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	res, err := agentenroll.Enroll(ctx, grpcAddr, plaintext, "0.1.0-e2e", agentPub, &lmdmv1.HardwareFingerprint{
		Hostname: "PC-HB-E2E",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	agentBus, err := agentbus.Connect(ctx, natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer agentBus.Close()

	runner := agentrunner.New(agentBus, res.DeviceID, "0.1.0-e2e", 250*time.Millisecond)
	runCtx, runCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer runCancel()
	go func() { _ = runner.Run(runCtx) }()

	deviceUUID := uuid.MustParse(res.DeviceID)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := deviceRepo.FindByID(ctx, tenantID, deviceUUID)
		if err == nil && got.LastSeen != nil && got.AgentVersion != nil && *got.AgentVersion == "0.1.0-e2e" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("device.last_seen never reflected the heartbeat within 5s")
}

func TestIntegrationInventoryLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

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
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		Cmd:          []string{"-js"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
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

	bus, err := natsbus.Connect(ctx, natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}

	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)
	keyPath := t.TempDir() + "/server.key"
	serverPriv, serverPub, err := serverkey.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	plaintext, _, err := tokenRepo.Create(ctx, tokens.CreateRequest{
		TenantID:    tenantID,
		Description: "e2e inv",
		MaxUses:     1,
		TTL:         time.Hour,
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	srv, err := server.New(httpAddr, grpcAddr, http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}
	endpoints := &lmdmv1.ServerEndpoints{NatsUrl: natsURL, GrpcUrl: grpcAddr, ApiUrl: "http://" + httpAddr}
	enrollSvc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour)
	lmdmv1.RegisterEnrollmentServiceServer(srv.GRPC(), enrollSvc)

	invIng := inventoryingester.New(bus, deviceRepo)
	if err := invIng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer invIng.Stop()

	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()
	select {
	case e := <-errs:
		t.Fatalf("server failed: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	// Agent-side: enroll, run the inventory runner briefly.
	_, agentPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	res, err := agentenroll.Enroll(ctx, grpcAddr, plaintext, "0.1.0-e2e-inv", agentPub, &lmdmv1.HardwareFingerprint{
		Hostname: "PC-INV-E2E",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	agentBus, err := agentbus.Connect(ctx, natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer agentBus.Close()

	runner := agentinventoryrunner.New(agentBus, res.DeviceID, 250*time.Millisecond)
	runCtx, runCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer runCancel()
	go func() { _ = runner.Run(runCtx) }()

	// Poll DB until we see a row in device_inventory for this device.
	deviceUUID := uuid.MustParse(res.DeviceID)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var id uuid.UUID
		err := pool.QueryRow(ctx,
			`SELECT device_id FROM device_inventory WHERE device_id = $1`, deviceUUID,
		).Scan(&id)
		if err == nil && id == deviceUUID {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("device_inventory was not populated within 5s")
}
