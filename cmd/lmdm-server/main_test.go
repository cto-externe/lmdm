package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/lmdm/lmdm/internal/db"
	"github.com/lmdm/lmdm/internal/natsbus"
	"github.com/lmdm/lmdm/internal/server"
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
		"db":   server.HealthCheckerFunc(func(ctx context.Context) error { return pool.Ping(ctx) }),
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
	defer srv.Shutdown(5 * time.Second)

	// Wait until /healthz is reachable.
	url := "http://" + httpAddr + "/healthz"
	deadline := time.Now().Add(10 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get(url)
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
	defer resp.Body.Close()
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
