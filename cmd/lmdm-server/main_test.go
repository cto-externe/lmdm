// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agentbus"
	"github.com/cto-externe/lmdm/internal/agentenroll"
	"github.com/cto-externe/lmdm/internal/agentinventoryrunner"
	"github.com/cto-externe/lmdm/internal/agentpolicy"
	"github.com/cto-externe/lmdm/internal/agentrunner"
	"github.com/cto-externe/lmdm/internal/api"
	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/complianceingester"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/grpcservices"
	"github.com/cto-externe/lmdm/internal/inventoryingester"
	"github.com/cto-externe/lmdm/internal/natsbus"
	"github.com/cto-externe/lmdm/internal/patchingester"
	"github.com/cto-externe/lmdm/internal/policy"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
	profilesRepo "github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/server"
	"github.com/cto-externe/lmdm/internal/serverkey"
	"github.com/cto-externe/lmdm/internal/statusingester"
	"github.com/cto-externe/lmdm/internal/tokens"
	"github.com/cto-externe/lmdm/internal/users"
)

// testAccessToken mints a signed admin JWT for tests without going through
// the /auth/login + MFA flow. The signer is the same one the server handlers
// use to verify access tokens, so tokens minted here are fully valid.
func testAccessToken(t *testing.T, signer *auth.JWTSigner, tenantID uuid.UUID) string {
	t.Helper()
	tok, err := signer.IssueAccess(uuid.New(), tenantID, auth.RoleAdmin, "it@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// authedGet issues a GET with a Bearer token attached.
func authedGet(t *testing.T, url, bearer string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// authedPost issues a POST with a Bearer token and JSON body.
func authedPost(t *testing.T, url, bearer, contentType, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// newTestAPIDeps returns api.Deps pre-wired with a test JWT signer, encryption
// key, auth.Service, users repo, audit writer, and generous rate limits so
// integration tests can authenticate without hitting the live /auth/login
// flow. Returns the signer so callers can mint access tokens.
func newTestAPIDeps(t *testing.T, pool *db.Pool, deviceRepo *devices.Repository, tokenRepo *tokens.Repository, profRepo *profilesRepo.Repository, nc *nats.Conn, tenantID uuid.UUID) (*api.Deps, *auth.JWTSigner) {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := auth.NewJWTSigner(pk, 15*time.Minute)
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}
	usersRepo := users.New(pool)
	auditWriter := audit.NewWriter(pool)
	authSvc := &auth.Service{
		Users:    usersRepo,
		Audit:    auditWriter,
		Signer:   signer,
		EncKey:   encKey,
		TenantID: tenantID,
		Issuer:   "LMDM",
	}
	return &api.Deps{
		Pool:           pool,
		Devices:        deviceRepo,
		Tokens:         tokenRepo,
		Profiles:       profRepo,
		Users:          usersRepo,
		Audit:          auditWriter,
		Auth:           authSvc,
		Signer:         signer,
		LoginRateLimit: auth.NewRateLimiter(1000, time.Minute),
		MFARateLimit:   auth.NewRateLimiter(1000, time.Minute),
		NATS:           nc,
		TenantID:       tenantID,
	}, signer
}

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
	svc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour, nil)
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
	enrollSvc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour, nil)
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
	enrollSvc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour, nil)
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

	// Poll DB until we see a row in device_inventory for this device AND
	// the JSONB payload contains the hostname we reported. This catches
	// silent protojson marshaling bugs that would leave the row in place
	// with an empty {} payload.
	deviceUUID := uuid.MustParse(res.DeviceID)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var hostname string
		var schemaVersion int
		err := pool.QueryRow(ctx,
			`SELECT report_json->'network'->>'hostname',
			        (report_json->>'schema_version')::int
			   FROM device_inventory WHERE device_id = $1`, deviceUUID,
		).Scan(&hostname, &schemaVersion)
		// Hostname must be non-empty (came from os.Hostname() on the test
		// host) and schema_version must be 1 (proves protojson populated
		// it, not an empty {}).
		if err == nil && hostname != "" && schemaVersion == 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("device_inventory JSONB was not populated correctly within 5s")
}

func TestIntegrationPolicyFlowPublishesCompliance(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
	serverPriv, serverPub, _ := serverkey.LoadOrGenerate(keyPath)
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	plaintext, _, _ := tokenRepo.Create(ctx, tokens.CreateRequest{
		TenantID: tenantID, Description: "policy-e2e", MaxUses: 1, TTL: time.Hour, CreatedBy: "test",
	})

	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	srv, _ := server.New(httpAddr, grpcAddr, http.NewServeMux())
	endpoints := &lmdmv1.ServerEndpoints{NatsUrl: natsURL, GrpcUrl: grpcAddr}
	enrollSvc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour, nil)
	lmdmv1.RegisterEnrollmentServiceServer(srv.GRPC(), enrollSvc)

	compIng := complianceingester.New(bus, pool)
	if err := compIng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer compIng.Stop()

	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()
	select {
	case e := <-errs:
		t.Fatalf("server: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	_, agentPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	res, err := agentenroll.Enroll(ctx, grpcAddr, plaintext, "0.1.0", agentPub, &lmdmv1.HardwareFingerprint{Hostname: "PC-POL"})
	if err != nil {
		t.Fatal(err)
	}

	// Agent side: connect NATS, start policy handler.
	agentNC, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer agentNC.Close()

	snapRoot := t.TempDir()
	handler := agentpolicy.NewHandler(agentpolicy.HandlerOptions{
		NC:        agentNC,
		ServerPub: res.ServerSigningKey,
		Registry:  policy.DefaultRegistry(),
		DeviceID:  res.DeviceID,
		SnapRoot:  snapRoot,
		Store:     agentpolicy.NewProfileStore(t.TempDir()),
	})
	if err := handler.Start(); err != nil {
		t.Fatal(err)
	}
	defer handler.Stop()

	// Send a signed empty profile (no actions = instantly compliant).
	profileYAML := []byte("kind: profile\nmetadata:\n  name: e2e-test\n  version: \"1.0\"\npolicies: []\n")
	sig, _ := pqhybrid.Sign(serverPriv, profileYAML)
	cmdEnv := &lmdmv1.CommandEnvelope{
		CommandId: "cmd-pol-1",
		Command: &lmdmv1.CommandEnvelope_ApplyProfile{
			ApplyProfile: &lmdmv1.ApplyProfileCommand{
				ProfileId:      &lmdmv1.ProfileID{Id: "prof-e2e"},
				Version:        "1.0",
				ProfileContent: profileYAML,
				ProfileSignature: &lmdmv1.HybridSignature{
					Ed25519: sig.Ed25519,
					MlDsa:   sig.MLDSA,
				},
			},
		},
	}
	cmdData, _ := proto.Marshal(cmdEnv)
	if err := agentNC.Publish("fleet.agent."+res.DeviceID+".commands", cmdData); err != nil {
		t.Fatal(err)
	}
	_ = agentNC.Flush()

	// Poll for compliance report in DB.
	deviceUUID := uuid.MustParse(res.DeviceID)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var status string
		err := pool.QueryRow(ctx,
			`SELECT overall_status FROM compliance_reports WHERE device_id = $1`, deviceUUID,
		).Scan(&status)
		if err == nil && status == "compliant" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("compliance report not found within 5s")
}

func TestIntegrationRESTAPIListDevicesAndTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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

	// Build server with enrollment + REST API.
	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	mux := http.NewServeMux()
	mux.Handle("/healthz", server.NewHealthHandler(map[string]server.HealthChecker{}))
	apiDeps, signer := newTestAPIDeps(t, pool, deviceRepo, tokenRepo,
		profilesRepo.NewRepository(pool, serverPriv), bus.NC(), tenantID)
	mux.Handle("/api/", api.Router(apiDeps))

	srv, err := server.New(httpAddr, grpcAddr, mux)
	if err != nil {
		t.Fatal(err)
	}
	enrollSvc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub,
		&lmdmv1.ServerEndpoints{NatsUrl: natsURL, GrpcUrl: grpcAddr}, time.Hour, nil)
	lmdmv1.RegisterEnrollmentServiceServer(srv.GRPC(), enrollSvc)

	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()
	select {
	case e := <-errs:
		t.Fatalf("server: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	baseURL := "http://" + httpAddr
	bearer := testAccessToken(t, signer, tenantID)

	// 1. Create a token via REST API.
	tokenBody := `{"description":"api-test","max_uses":2,"ttl_seconds":3600}`
	resp := authedPost(t, baseURL+"/api/v1/tokens", bearer, "application/json", tokenBody)
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("POST /tokens: %d %s", resp.StatusCode, body)
	}
	var tokenResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenResp)
	_ = resp.Body.Close()
	if tokenResp.Data.Token == "" {
		t.Fatal("token plaintext must be returned")
	}

	// 2. Enroll a device using that token.
	_, agentPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	enrollRes, err := agentenroll.Enroll(ctx, grpcAddr, tokenResp.Data.Token, "0.1.0-api",
		agentPub, &lmdmv1.HardwareFingerprint{Hostname: "PC-API-TEST"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// 3. List devices via REST API — should have 1.
	resp2 := authedGet(t, baseURL+"/api/v1/devices", bearer)
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != 200 {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("GET /devices: %d %s", resp2.StatusCode, body)
	}
	var devicesResp struct {
		Data  []json.RawMessage `json:"data"`
		Total int               `json:"total"`
	}
	_ = json.NewDecoder(resp2.Body).Decode(&devicesResp)
	if devicesResp.Total != 1 {
		t.Errorf("total devices = %d, want 1", devicesResp.Total)
	}

	// 4. Get device detail.
	resp3 := authedGet(t, baseURL+"/api/v1/devices/"+enrollRes.DeviceID, bearer)
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != 200 {
		body, _ := io.ReadAll(resp3.Body)
		t.Fatalf("GET /devices/{id}: %d %s", resp3.StatusCode, body)
	}

	// 5. List tokens — should have 1.
	resp4 := authedGet(t, baseURL+"/api/v1/tokens", bearer)
	defer func() { _ = resp4.Body.Close() }()
	if resp4.StatusCode != 200 {
		body, _ := io.ReadAll(resp4.Body)
		t.Fatalf("GET /tokens: %d %s", resp4.StatusCode, body)
	}
}

func TestIntegrationPatchReportFlowToRESTAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
		TenantID: tenantID, Description: "patch-e2e", MaxUses: 1, TTL: time.Hour, CreatedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build server with enrollment + REST API + patch ingester.
	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	mux := http.NewServeMux()
	apiDeps, signer := newTestAPIDeps(t, pool, deviceRepo, tokenRepo,
		profilesRepo.NewRepository(pool, serverPriv), bus.NC(), tenantID)
	mux.Handle("/api/", api.Router(apiDeps))
	srv, err := server.New(httpAddr, grpcAddr, mux)
	if err != nil {
		t.Fatal(err)
	}
	enrollSvc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub,
		&lmdmv1.ServerEndpoints{NatsUrl: natsURL, GrpcUrl: grpcAddr}, time.Hour, nil)
	lmdmv1.RegisterEnrollmentServiceServer(srv.GRPC(), enrollSvc)

	patchIng := patchingester.New(bus, pool)
	if err := patchIng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer patchIng.Stop()

	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()
	select {
	case e := <-errs:
		t.Fatalf("server: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	// Enroll a device.
	_, agentPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	enrollRes, err := agentenroll.Enroll(ctx, grpcAddr, plaintext, "0.1.0-patch",
		agentPub, &lmdmv1.HardwareFingerprint{Hostname: "PC-PATCH-E2E"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Publish a mock PatchReport on NATS.
	agentNC, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer agentNC.Close()

	report := &lmdmv1.PatchReport{
		DeviceId:  &lmdmv1.DeviceID{Id: enrollRes.DeviceID},
		Timestamp: timestamppb.New(time.Now().UTC()),
		Updates: []*lmdmv1.AvailableUpdate{
			{Name: "openssl", CurrentVersion: "3.0.2-15", AvailableVersion: "3.0.2-16", Security: true, Source: "apt"},
		},
		RebootRequired: false,
	}
	reportData, err := proto.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := agentNC.Publish("fleet.agent."+enrollRes.DeviceID+".patches", reportData); err != nil {
		t.Fatal(err)
	}
	_ = agentNC.Flush()

	baseURL := "http://" + httpAddr
	bearer := testAccessToken(t, signer, tenantID)

	// Poll GET /api/v1/devices/<id>/updates until total == 1.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/devices/"+enrollRes.DeviceID+"/updates", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var body struct {
				Data  []json.RawMessage `json:"data"`
				Total int               `json:"total"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			_ = resp.Body.Close()
			if body.Total == 1 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("updates not visible via REST API within 5s")
}
