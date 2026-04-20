// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentenroll

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

// enrollSpy captures the latest EnrollRequest it received so tests can
// assert the client wired CSR / pubkey bytes correctly.
type enrollSpy struct {
	lmdmv1.UnimplementedEnrollmentServiceServer
	lastReq    *lmdmv1.EnrollRequest
	respCSR    []byte
	respCA     []byte
	respDevice string
}

func (s *enrollSpy) Enroll(_ context.Context, req *lmdmv1.EnrollRequest) (*lmdmv1.EnrollResponse, error) {
	s.lastReq = req
	return &lmdmv1.EnrollResponse{
		DeviceId:            &lmdmv1.DeviceID{Id: s.respDevice},
		AgentCertificate:    []byte("signed-hybrid"),
		ServerSigningKey:    &lmdmv1.HybridPublicKey{Ed25519: []byte("ed"), MlDsa: []byte("ml")},
		TenantId:            &lmdmv1.TenantID{Id: "tenant"},
		Endpoints:           &lmdmv1.ServerEndpoints{GrpcUrl: "x", NatsUrl: "x", ApiUrl: "x"},
		AgentCertificatePem: s.respCSR,
		CaCertificatePem:    s.respCA,
	}, nil
}

// TestEnroll_ForwardsCSRAndSurfacesX509 verifies the client sends csr_pem in
// the request and exposes agent_certificate_pem + ca_certificate_pem in the
// returned Result. Uses an insecure loopback server so no TLS wiring is
// required — the transport path is covered by e2e tests in a later task.
func TestEnroll_ForwardsCSRAndSurfacesX509(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })

	spy := &enrollSpy{
		respCSR:    []byte("-----BEGIN CERTIFICATE-----\nAGENT\n-----END CERTIFICATE-----\n"),
		respCA:     []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"),
		respDevice: "11111111-1111-1111-1111-111111111111",
	}
	gs := grpc.NewServer()
	lmdmv1.RegisterEnrollmentServiceServer(gs, spy)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	agentPub := &pqhybrid.SigningPublicKey{Ed25519: []byte("pub-ed"), MLDSA: []byte("pub-ml")}
	csrPEM := []byte("-----BEGIN CERTIFICATE REQUEST-----\nFAKECSR\n-----END CERTIFICATE REQUEST-----\n")

	res, err := Enroll(ctx, lis.Addr().String(), "tok", "0.1.0", agentPub,
		&lmdmv1.HardwareFingerprint{Hostname: "pc-csr"}, csrPEM, nil)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	if spy.lastReq == nil {
		t.Fatal("spy did not receive request")
	}
	if string(spy.lastReq.GetCsrPem()) != string(csrPEM) {
		t.Fatalf("csr_pem not forwarded: got %q want %q", spy.lastReq.GetCsrPem(), csrPEM)
	}
	if string(res.AgentCertPEM) != string(spy.respCSR) {
		t.Fatalf("AgentCertPEM mismatch: got %q", res.AgentCertPEM)
	}
	if string(res.CAPEM) != string(spy.respCA) {
		t.Fatalf("CAPEM mismatch: got %q", res.CAPEM)
	}
	if res.DeviceID != spy.respDevice {
		t.Fatalf("DeviceID mismatch: got %q", res.DeviceID)
	}
}
