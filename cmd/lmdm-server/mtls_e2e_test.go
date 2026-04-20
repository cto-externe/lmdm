// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agentenroll"
	"github.com/cto-externe/lmdm/internal/agenttls"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/grpcservices"
	"github.com/cto-externe/lmdm/internal/natsbus"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
	"github.com/cto-externe/lmdm/internal/revocation"
	"github.com/cto-externe/lmdm/internal/server"
	"github.com/cto-externe/lmdm/internal/serverkey"
	"github.com/cto-externe/lmdm/internal/tlspki"
	"github.com/cto-externe/lmdm/internal/tokens"
)

// mtlsE2EStack bundles everything an mTLS e2e test needs: running gRPC +
// HTTP servers terminated with an mTLS-configured tls.Config, the authoritative
// CA, the revocation cache driving the TLS VerifyPeerCertificate callback, the
// revocation repo for persisting revocations, and the enrollment token callers
// consume to drive the Enroll RPC.
type mtlsE2EStack struct {
	grpcAddr   string
	caCertPEM  []byte
	tenantID   uuid.UUID
	tokenPlain string
	revRepo    *revocation.Repository
	revCache   *tlspki.RevocationCache
	deviceRepo *devices.Repository
}

// setupMTLSE2EStack spins up postgres + nats testcontainers, generates a fresh
// CA, issues a server cert with DNS=localhost + IP=127.0.0.1, builds an
// mTLS-enforcing tls.Config (ClientAuth=VerifyClientCertIfGiven so the
// unauthenticated Enroll RPC still gets through, VerifyPeerCertificate wired
// to the revocation cache), wires the EnrollmentService with the real CA, and
// starts the server. Returns the handle + a cleanup that tears everything
// down in reverse.
//
// NATS runs plaintext inside the testcontainer (the real deployment uses mTLS
// for NATS too, but that requires cert rotation plumbing that is out of scope
// for this test).
func setupMTLSE2EStack(t *testing.T, ctx context.Context) (*mtlsE2EStack, func()) {
	t.Helper()

	// --- postgres ---
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("lmdm"), postgres.WithUsername("lmdm"), postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}

	// --- nats ---
	natsReq := testcontainers.ContainerRequest{
		Image: "nats:2.10-alpine", ExposedPorts: []string{"4222/tcp"},
		Cmd: []string{"-js"}, WaitingFor: wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	natsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: natsReq, Started: true,
	})
	if err != nil {
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	natsHost, _ := natsC.Host(ctx)
	natsPort, _ := natsC.MappedPort(ctx, "4222/tcp")
	natsURL := "nats://" + natsHost + ":" + natsPort.Port()
	bus, err := natsbus.Connect(ctx, natsURL, nil)
	if err != nil {
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	if err := bus.EnsureStreams(ctx); err != nil {
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}

	// --- CA + server cert ---
	caCertPEM, caKeyPEM, err := tlspki.GenerateCA("lmdm-mtls-e2e CA")
	if err != nil {
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatal(err)
	}
	caDir := t.TempDir()
	caCertPath := caDir + "/ca.crt"
	caKeyPath := caDir + "/ca.key"
	if err := os.WriteFile(caCertPath, caCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caKeyPath, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := tlspki.LoadCA(caCertPath, caKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	serverCertPEM, serverKeyPEM, err := ca.GenerateServerCert(tlspki.ServerCertOptions{
		CommonName: "lmdm-server",
		DNSNames:   []string{"localhost"},
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// --- revocation cache + repo ---
	revRepo := revocation.New(pool)
	revCache := tlspki.NewRevocationCache()

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(ca.Cert)
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		RootCAs:      clientCAPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
		// Wrap the cache's VerifyPeerCertificate so unauthenticated Enroll
		// clients (no cert yet) still get through. Mirrors the semantics
		// main.go documents around VerifyClientCertIfGiven; the raw cache
		// callback is strict and refuses empty chains, which works at the
		// unit-test level but not when exercised over a real TLS handshake.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 {
				return nil
			}
			return revCache.VerifyPeerCertificate(rawCerts, verifiedChains)
		},
		// Resumed sessions skip VerifyPeerCertificate; mirror main.go and
		// re-check the revocation cache from VerifyConnection too.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return nil
			}
			if revCache.Has(cs.PeerCertificates[0].SerialNumber.String()) {
				return tlspki.ErrCertificateRevoked
			}
			return nil
		},
	}

	// --- server-signing pqhybrid key (for the SignedAgentCert path) ---
	keyPath := t.TempDir() + "/server.key"
	serverPriv, serverPub, err := serverkey.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// --- server + EnrollmentService ---
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)

	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	mux := http.NewServeMux()
	srv, err := server.New(httpAddr, grpcAddr, mux, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	endpoints := &lmdmv1.ServerEndpoints{NatsUrl: natsURL, GrpcUrl: grpcAddr, ApiUrl: "https://" + httpAddr}
	enrollSvc := grpcservices.NewEnrollmentService(
		tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, time.Hour, ca,
	)
	lmdmv1.RegisterEnrollmentServiceServer(srv.GRPC(), enrollSvc)

	errs := srv.Start()
	select {
	case e := <-errs:
		_ = srv.Shutdown(2 * time.Second)
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
		t.Fatalf("server failed to start: %v", e)
	case <-time.After(200 * time.Millisecond):
	}

	// --- enrollment token ---
	plaintext, _, err := tokenRepo.Create(ctx, tokens.CreateRequest{
		TenantID:    tenantID,
		Description: "mtls-e2e",
		MaxUses:     5,
		TTL:         time.Hour,
		CreatedBy:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		_ = srv.Shutdown(5 * time.Second)
		bus.Close()
		_ = natsC.Terminate(ctx)
		pool.Close()
		_ = pg.Terminate(ctx)
	}

	return &mtlsE2EStack{
		grpcAddr:   grpcAddr,
		caCertPEM:  caCertPEM,
		tenantID:   tenantID,
		tokenPlain: plaintext,
		revRepo:    revRepo,
		revCache:   revCache,
		deviceRepo: deviceRepo,
	}, cleanup
}

// enrollTestAgent drives one full mTLS enrollment round trip: generates a
// fresh agent ECDSA keypair + CSR, calls agentenroll.Enroll over server-auth
// TLS (no client cert yet), returns the Enroll result + keypair + parsed
// leaf certificate. The Enroll call consumes one use from the seeded token.
func enrollTestAgent(t *testing.T, ctx context.Context, stack *mtlsE2EStack, hostname string) (*agentenroll.Result, *agenttls.Keypair, *x509.Certificate) {
	t.Helper()
	kp, err := agenttls.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	// Pre-enrollment we don't know the device UUID yet, so use the hostname
	// as placeholder CN. The server replaces it with the issued UUID.
	csrPEM, err := kp.BuildCSR(hostname, hostname)
	if err != nil {
		t.Fatal(err)
	}
	_, agentPub, err := pqhybrid.GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := agentenroll.Enroll(ctx, stack.grpcAddr, stack.tokenPlain,
		"0.1.0-mtls-e2e", agentPub,
		&lmdmv1.HardwareFingerprint{Hostname: hostname},
		csrPEM, stack.caCertPEM)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if len(res.AgentCertPEM) == 0 {
		t.Fatal("Enroll did not return AgentCertPEM")
	}
	if len(res.CAPEM) == 0 {
		t.Fatal("Enroll did not return CAPEM")
	}
	block, _ := pem.Decode(res.AgentCertPEM)
	if block == nil {
		t.Fatal("agent cert pem decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse agent cert: %v", err)
	}
	return res, kp, cert
}

// TestIntegrationMTLSEnrollAndRevoke drives the full mTLS transport:
//  1. Agent enrolls over server-auth TLS, receiving an X.509 client cert.
//  2. Agent opens an mTLS gRPC connection with the issued cert + key and
//     successfully calls RenewCertificate (proves the mTLS handshake works).
//  3. Admin revokes the cert by inserting into revoked_certificates and
//     synchronously populating the in-memory cache (the cache is normally
//     populated by the NATS broadcast subscriber; we call Add directly to
//     keep the test free of NATS timing flakes).
//  4. Agent attempts another mTLS RPC with the now-revoked cert. The TLS
//     handshake fails because VerifyPeerCertificate returns
//     ErrCertificateRevoked.
//
// What's covered: CSR signing, mTLS handshake against the real server
// tls.Config, revocation cache → VerifyPeerCertificate path, tenant-scoped
// revocation repo. What's not covered: NATS broadcast of revocations (the
// cache.Add call short-circuits the subscriber), periodic full refresh,
// rotation of the server's own cert.
func TestIntegrationMTLSEnrollAndRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	stack, cleanup := setupMTLSE2EStack(t, ctx)
	defer cleanup()

	// 1. Enroll.
	res, kp, cert := enrollTestAgent(t, ctx, stack, "pc-mtls-enroll")
	serial := cert.SerialNumber.String()

	// 2. Build agent mTLS tlsConfig + RenewClient; do a successful renew.
	keyPEM, err := kp.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	// grpcAddr is 127.0.0.1:port; server cert has DNS=localhost + IP=127.0.0.1.
	// Match what agentenroll.Enroll does: use the host part of grpcAddr.
	serverName, _, _ := net.SplitHostPort(stack.grpcAddr)
	agentTLS, err := agenttls.BuildClientTLSConfig(res.AgentCertPEM, keyPEM, res.CAPEM, serverName)
	if err != nil {
		t.Fatal(err)
	}
	renewClient, err := agentenroll.NewRenewClient(stack.grpcAddr, agentTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = renewClient.Close() }()

	// Issue a new CSR signed by the same agent key (CN must match cert CN,
	// which is the device UUID assigned at enrollment).
	deviceUUID := res.DeviceID
	csr2, err := kp.BuildCSR(deviceUUID, "pc-mtls-enroll")
	if err != nil {
		t.Fatal(err)
	}
	newCert, err := renewClient.RenewCertificate(ctx, csr2)
	if err != nil {
		t.Fatalf("RenewCertificate (pre-revoke) failed: %v", err)
	}
	if len(newCert) == 0 {
		t.Fatal("RenewCertificate returned empty cert")
	}

	// 3. Revoke the ORIGINAL cert (the one still pinned in agentTLS). Insert
	// into the repo and prime the in-memory cache (the NATS broadcast path
	// is tested separately).
	devUUID := uuid.MustParse(deviceUUID)
	if err := stack.revRepo.Revoke(ctx, stack.tenantID, serial, &devUUID, nil, "e2e-test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	stack.revCache.Add(serial)

	// 4. Next mTLS handshake must fail. gRPC's NewClient is lazy so the
	// handshake only happens on the first RPC. We build a fresh RenewClient
	// so there's no pre-warmed connection.
	reusableTLS, err := agenttls.BuildClientTLSConfig(res.AgentCertPEM, keyPEM, res.CAPEM, serverName)
	if err != nil {
		t.Fatal(err)
	}
	revokedClient, err := agentenroll.NewRenewClient(stack.grpcAddr, reusableTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revokedClient.Close() }()
	csr3, err := kp.BuildCSR(deviceUUID, "pc-mtls-enroll")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revokedClient.RenewCertificate(ctx, csr3); err == nil {
		t.Fatal("RenewCertificate with revoked cert must fail, got nil error")
	} else {
		// Don't overfit; just make the failure mode unambiguous.
		t.Logf("post-revoke RPC failed as expected: %v", err)
		if !strings.Contains(strings.ToLower(err.Error()), "revoked") &&
			!strings.Contains(strings.ToLower(err.Error()), "bad certificate") &&
			!strings.Contains(strings.ToLower(err.Error()), "tls") {
			t.Errorf("unexpected error kind (want TLS/revocation failure): %v", err)
		}
	}
}

// TestIntegrationMTLSRenewal enrolls once, performs a renewal round trip,
// and asserts the issued cert is genuinely distinct from the original:
// different serial, later NotAfter, same Subject.CommonName (which equals
// the device UUID assigned at enrollment).
//
// What's covered: enrollment CSR signing, mTLS handshake, RenewCertificate
// RPC, server-side CSR-CN-vs-peer-CN check. What's not covered: the
// agenttls.Runner ticker loop (tested in renewer_test.go), disk persistence
// of the renewed credentials (agenttls.Store handles that independently).
func TestIntegrationMTLSRenewal(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	stack, cleanup := setupMTLSE2EStack(t, ctx)
	defer cleanup()

	res, kp, origCert := enrollTestAgent(t, ctx, stack, "pc-mtls-renew")
	origSerial := origCert.SerialNumber.String()
	origNotAfter := origCert.NotAfter

	keyPEM, err := kp.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	serverName, _, _ := net.SplitHostPort(stack.grpcAddr)
	agentTLS, err := agenttls.BuildClientTLSConfig(res.AgentCertPEM, keyPEM, res.CAPEM, serverName)
	if err != nil {
		t.Fatal(err)
	}
	renewClient, err := agentenroll.NewRenewClient(stack.grpcAddr, agentTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = renewClient.Close() }()

	// Give the server clock a tick so NotAfter is strictly greater than the
	// original (both are now+ttl so identical timestamps would be a valid
	// outcome — sleep 1.1s so the second NotAfter is at least ~1s later).
	time.Sleep(1100 * time.Millisecond)

	// Renew with a fresh keypair, as the production Runner does — this
	// exercises the server's "sign any valid CSR whose CN matches peer CN"
	// logic rather than the degenerate same-key-same-CSR case.
	newKP, err := agenttls.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	deviceUUID := res.DeviceID
	csr, err := newKP.BuildCSR(deviceUUID, "pc-mtls-renew")
	if err != nil {
		t.Fatal(err)
	}
	newCertPEM, err := renewClient.RenewCertificate(ctx, csr)
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	block, _ := pem.Decode(newCertPEM)
	if block == nil {
		t.Fatal("renewed cert pem decode failed")
	}
	newCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}

	if newCert.SerialNumber.String() == origSerial {
		t.Errorf("renewed cert has same serial as original: %s", origSerial)
	}
	if !newCert.NotAfter.After(origNotAfter) {
		t.Errorf("renewed cert NotAfter (%s) not after original (%s)",
			newCert.NotAfter, origNotAfter)
	}
	if newCert.Subject.CommonName != deviceUUID {
		t.Errorf("renewed cert CN = %q, want %q", newCert.Subject.CommonName, deviceUUID)
	}
}
