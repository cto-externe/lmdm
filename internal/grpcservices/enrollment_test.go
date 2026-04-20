// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package grpcservices

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agenttls"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/identity"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
	"github.com/cto-externe/lmdm/internal/tlspki"
	"github.com/cto-externe/lmdm/internal/tokens"
)

// writeTestCA generates a fresh CA, writes it to tempdir, loads it and
// returns the loaded CA plus the cert PEM bytes (useful for building a
// roots pool in tests).
func writeTestCA(t *testing.T) (*tlspki.CA, []byte) {
	t.Helper()
	certPEM, keyPEM, err := tlspki.GenerateCA("lmdm-test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := tlspki.LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return ca, certPEM
}

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

	ca, caPEM := writeTestCA(t)

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
	svc := NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, 365*24*time.Hour, ca)
	lmdmv1.RegisterEnrollmentServiceServer(gs, svc)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	// Agent side: generate keypairs (PQ signing + ECDSA X.509) and a CSR.
	_, agentPub, err := pqhybrid.GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := agenttls.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// CN in the CSR is overwritten by the CA on signing — we don't know
	// the device UUID yet at this point, so just use a placeholder.
	csrPEM, err := kp.BuildCSR("pending", "PC-TEST-01")
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
		CsrPem:       csrPEM,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Validate response shape.
	if resp.GetDeviceId().GetId() == "" {
		t.Fatal("device_id missing")
	}
	if len(resp.GetAgentCertificate()) == 0 {
		t.Fatal("agent_certificate (SignedAgentCert) missing — defense-in-depth broken")
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

	// X.509 path: assert the agent cert is non-empty, parseable, and
	// chain-verifies against the returned CA cert.
	if len(resp.GetAgentCertificatePem()) == 0 {
		t.Fatal("agent_certificate_pem missing")
	}
	if len(resp.GetCaCertificatePem()) == 0 {
		t.Fatal("ca_certificate_pem missing")
	}
	if string(resp.GetCaCertificatePem()) != string(caPEM) {
		t.Errorf("ca_certificate_pem does not match the CA we configured")
	}

	leafBlock, _ := pem.Decode(resp.GetAgentCertificatePem())
	if leafBlock == nil {
		t.Fatal("agent_certificate_pem decode failed")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse agent cert: %v", err)
	}
	if leaf.Subject.CommonName != resp.GetDeviceId().GetId() {
		t.Errorf("leaf CN = %q, want device_id %q", leaf.Subject.CommonName, resp.GetDeviceId().GetId())
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("leaf chain verification failed: %v", err)
	}

	// DB should now have the device and its current_cert_serial.
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

// TestEnroll_NoCSR_ReturnsResponseWithoutX509 verifies that when a legacy
// agent omits csr_pem, the handler still returns the SignedAgentCert proto
// (defense-in-depth) with empty AgentCertificatePem / CaCertificatePem.
// This keeps backward compatibility during the mTLS transition.
func TestEnroll_NoCSR_ReturnsResponseWithoutX509(t *testing.T) {
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
		TenantID:  tenantID,
		MaxUses:   1,
		TTL:       time.Hour,
		CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}

	ca, _ := writeTestCA(t)

	svc := NewEnrollmentService(tokenRepo, deviceRepo, serverPriv, serverPub,
		&lmdmv1.ServerEndpoints{}, time.Hour, ca)
	_, agentPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	resp, err := svc.Enroll(ctx, &lmdmv1.EnrollRequest{
		EnrollmentToken: plaintext,
		AgentPublicKey:  &lmdmv1.HybridPublicKey{Ed25519: agentPub.Ed25519, MlDsa: agentPub.MLDSA},
		Hardware:        &lmdmv1.HardwareFingerprint{Hostname: "PC-LEGACY"},
		// no CsrPem set
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(resp.GetAgentCertificate()) == 0 {
		t.Fatal("SignedAgentCert (defense-in-depth) must still be present")
	}
	if len(resp.GetAgentCertificatePem()) != 0 {
		t.Errorf("AgentCertificatePem should be empty when no csr supplied, got %d bytes", len(resp.GetAgentCertificatePem()))
	}
	if len(resp.GetCaCertificatePem()) != 0 {
		t.Errorf("CaCertificatePem should be empty when no csr supplied, got %d bytes", len(resp.GetCaCertificatePem()))
	}
}

// TestRenewCertificate tests the handler directly by constructing a gRPC
// peer context with a mTLS-validated leaf cert. A full mTLS-over-gRPC
// integration test is out of scope for this unit.
//
// The handler's best-effort SetCurrentCertSerial path only runs when the
// mTLS peer CN parses as a UUID. To keep this a pure unit test (no DB),
// we use a non-UUID CN so that branch is skipped.
func TestRenewCertificate(t *testing.T) {
	ca, _ := writeTestCA(t)

	const peerCN = "test-device-cn" // non-UUID → best-effort DB update is skipped

	kp, err := agenttls.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := kp.BuildCSR(peerCN, "")
	if err != nil {
		t.Fatal(err)
	}
	csrBlock, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Issue a "current" cert to impersonate an already-enrolled agent.
	currentCertPEM, err := ca.SignCSR(csr, peerCN, time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	currentBlock, _ := pem.Decode(currentCertPEM)
	currentCert, err := x509.ParseCertificate(currentBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	serverPriv, serverPub, err := pqhybrid.GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := &EnrollmentService{
		serverPriv: serverPriv,
		serverPub:  serverPub,
		certTTL:    time.Hour,
		ca:         ca,
	}

	peerCtx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{{currentCert}},
			},
		},
	})

	// Happy path: CSR CN matches peer CN → cert issued.
	newKp, err := agenttls.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	renewCSRPEM, err := newKp.BuildCSR(peerCN, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.RenewCertificate(peerCtx, &lmdmv1.RenewCertificateRequest{CsrPem: renewCSRPEM})
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if len(resp.GetNewCertificate()) == 0 {
		t.Fatal("new_certificate missing")
	}
	newBlock, _ := pem.Decode(resp.GetNewCertificate())
	if newBlock == nil {
		t.Fatal("new_certificate decode failed")
	}
	newCert, err := x509.ParseCertificate(newBlock.Bytes)
	if err != nil {
		t.Fatalf("parse new cert: %v", err)
	}
	if newCert.Subject.CommonName != peerCN {
		t.Errorf("new cert CN = %q, want %q", newCert.Subject.CommonName, peerCN)
	}

	// Permission denied: CSR CN does not match the peer's CN.
	mismatchCSR, err := newKp.BuildCSR("some-other-device", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.RenewCertificate(peerCtx, &lmdmv1.RenewCertificateRequest{CsrPem: mismatchCSR})
	if err == nil {
		t.Fatal("expected PermissionDenied for CN mismatch, got nil error")
	}

	// Unauthenticated: no mTLS peer at all.
	_, err = svc.RenewCertificate(context.Background(), &lmdmv1.RenewCertificateRequest{CsrPem: renewCSRPEM})
	if err == nil {
		t.Fatal("expected Unauthenticated without mTLS peer, got nil error")
	}

	// Unavailable: no CA wired.
	emptySvc := &EnrollmentService{certTTL: time.Hour}
	_, err = emptySvc.RenewCertificate(peerCtx, &lmdmv1.RenewCertificateRequest{CsrPem: renewCSRPEM})
	if err == nil {
		t.Fatal("expected Unavailable when CA is nil, got nil error")
	}
}
