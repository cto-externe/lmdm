// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentenroll

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/grpcservices"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
	"github.com/cto-externe/lmdm/internal/tokens"
)

func TestIntegrationEnrollClientHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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

	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)
	serverPriv, serverPub, err := pqhybrid.GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	plaintext, _, err := tokenRepo.Create(ctx, tokens.CreateRequest{
		TenantID:    tenantID,
		Description: "client-test",
		MaxUses:     1,
		TTL:         time.Hour,
		CreatedBy:   "tester",
	})
	if err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	endpoints := &lmdmv1.ServerEndpoints{NatsUrl: "nats://x", GrpcUrl: lis.Addr().String(), ApiUrl: "http://x"}
	svc := grpcservices.NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour, nil)
	lmdmv1.RegisterEnrollmentServiceServer(gs, svc)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	_, agentPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	res, err := Enroll(ctx, lis.Addr().String(), plaintext, "0.1.0-test", agentPub, &lmdmv1.HardwareFingerprint{
		Hostname: "PC-CLIENT-TEST",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.DeviceID == "" || len(res.SignedCert) == 0 {
		t.Fatal("incomplete result")
	}
	if res.ServerSigningKey == nil ||
		len(res.ServerSigningKey.Ed25519) == 0 ||
		len(res.ServerSigningKey.MLDSA) == 0 {
		t.Fatal("server pubkey missing")
	}
	if res.Endpoints == nil || res.Endpoints.GrpcUrl == "" {
		t.Fatal("endpoints missing")
	}
}
