package grpcservices

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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/identity"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
	"github.com/cto-externe/lmdm/internal/tokens"
)

func TestIntegrationEnrollHappyPath(t *testing.T) {
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
		Description: "e2e",
		GroupIDs:    []string{"workstations"},
		MaxUses:     1,
		TTL:         time.Hour,
		CreatedBy:   "tester",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start a real gRPC server with EnrollmentService registered.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	endpoints := &lmdmv1.ServerEndpoints{
		NatsUrl: "nats://localhost:4222",
		GrpcUrl: "localhost:50051",
		ApiUrl:  "https://localhost:443",
	}
	svc := NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, 365*24*time.Hour)
	lmdmv1.RegisterEnrollmentServiceServer(gs, svc)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	// Agent side: generate keypair, call Enroll.
	_, agentPub, err := pqhybrid.GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := lmdmv1.NewEnrollmentServiceClient(conn)

	resp, err := client.Enroll(ctx, &lmdmv1.EnrollRequest{
		EnrollmentToken: plaintext,
		AgentPublicKey: &lmdmv1.HybridPublicKey{
			Ed25519: agentPub.Ed25519,
			MlDsa:   agentPub.MLDSA,
		},
		Hardware: &lmdmv1.HardwareFingerprint{
			Hostname:     "PC-TEST-01",
			SerialNumber: "SN12345",
			Manufacturer: "ACME",
			Model:        "Latitude 7440",
			Os: &lmdmv1.OSInfo{
				Family:  lmdmv1.OSFamily_OS_FAMILY_DEBIAN,
				Name:    "ubuntu",
				Version: "24.04",
			},
		},
		AgentVersion: "0.1.0-test",
		FirstBoot:    true,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Validate response shape.
	if resp.GetDeviceId().GetId() == "" {
		t.Fatal("device_id missing")
	}
	if len(resp.GetAgentCertificate()) == 0 {
		t.Fatal("agent_certificate missing")
	}
	if resp.GetServerSigningKey() == nil ||
		len(resp.GetServerSigningKey().GetEd25519()) == 0 ||
		len(resp.GetServerSigningKey().GetMlDsa()) == 0 {
		t.Fatal("server_signing_key missing components")
	}
	if resp.GetEndpoints().GetGrpcUrl() != endpoints.GrpcUrl {
		t.Errorf("grpc endpoint mismatch")
	}

	// Verify the signed cert with the server's pubkey we received.
	var signed lmdmv1.SignedAgentCert
	if err := proto.Unmarshal(resp.GetAgentCertificate(), &signed); err != nil {
		t.Fatalf("unmarshal cert: %v", err)
	}
	srvPub := &pqhybrid.SigningPublicKey{
		Ed25519: resp.GetServerSigningKey().GetEd25519(),
		MLDSA:   resp.GetServerSigningKey().GetMlDsa(),
	}
	cert, err := identity.VerifyCert(&signed, srvPub)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	if cert.GetDeviceId().GetId() != resp.GetDeviceId().GetId() {
		t.Errorf("device_id in cert vs response mismatch")
	}

	// DB should now have the device.
	deviceID := uuid.MustParse(resp.GetDeviceId().GetId())
	got, err := deviceRepo.FindByID(ctx, tenantID, deviceID)
	if err != nil {
		t.Fatalf("device not in DB: %v", err)
	}
	if got.Hostname != "PC-TEST-01" {
		t.Errorf("hostname = %q", got.Hostname)
	}

	// Re-using the same token must fail (max_uses=1 already consumed).
	_, err = client.Enroll(ctx, &lmdmv1.EnrollRequest{
		EnrollmentToken: plaintext,
		AgentPublicKey:  &lmdmv1.HybridPublicKey{Ed25519: agentPub.Ed25519, MlDsa: agentPub.MLDSA},
		Hardware:        &lmdmv1.HardwareFingerprint{Hostname: "PC-X"},
	})
	if err == nil {
		t.Fatal("re-using exhausted token must fail")
	}
}
