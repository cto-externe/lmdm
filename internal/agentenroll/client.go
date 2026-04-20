// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agentenroll wraps the gRPC EnrollmentService.Enroll call into a
// transport-only helper. It does not persist anything — the caller decides
// where to store the returned cert and server pubkey.
package agentenroll

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

// Result is the agent-side view of an EnrollResponse.
type Result struct {
	DeviceID         string
	SignedCert       []byte                     // raw SignedAgentCert proto bytes
	ServerSigningKey *pqhybrid.SigningPublicKey // server's hybrid pubkey
	TenantID         string
	GroupIDs         []string
	SiteID           string
	Endpoints        *lmdmv1.ServerEndpoints
	IsRelay          bool
	AgentCertPEM     []byte // X.509 issued by server (PEM)
	CAPEM            []byte // CA chain for agent trust store (PEM)
}

// Enroll connects to the gRPC server, calls EnrollmentService.Enroll with the
// supplied token + agent pubkey + hardware fingerprint, and returns the
// parsed result.
//
// Transport rules:
//   - If caCertPEM is non-empty, the agent dials with server-auth TLS (TLS 1.3,
//     X25519MLKEM768 preferred) verifying the server against the supplied CA.
//     This is the normal enrollment path: the admin distributes the CA cert
//     alongside the enrollment token. The agent itself has no client cert yet
//     — the CSR being sent is what gets signed into one.
//   - If caCertPEM is empty, the agent dials insecure. Legacy fallback kept
//     for tests and bootstrap scenarios only; not used in production.
//
// If csrPEM is non-empty it is forwarded in the EnrollRequest so the server
// issues an X.509 agent certificate; the response's agent_certificate_pem and
// ca_certificate_pem are surfaced in Result for the caller to persist.
func Enroll(
	ctx context.Context,
	grpcAddr, token, agentVersion string,
	agentPub *pqhybrid.SigningPublicKey,
	hardware *lmdmv1.HardwareFingerprint,
	csrPEM []byte,
	caCertPEM []byte,
) (*Result, error) {
	var creds credentials.TransportCredentials
	if len(caCertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertPEM) {
			return nil, errors.New("agentenroll: invalid CA PEM")
		}
		host, _, err := net.SplitHostPort(grpcAddr)
		if err != nil {
			// Accept bare hostnames (no port) as-is.
			host = grpcAddr
		}
		cfg := &tls.Config{
			RootCAs:    pool,
			ServerName: host,
			MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
			},
		}
		creds = credentials.NewTLS(cfg)
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("agentenroll: dial %s: %w", grpcAddr, err)
	}
	defer func() { _ = conn.Close() }()

	resp, err := lmdmv1.NewEnrollmentServiceClient(conn).Enroll(ctx, &lmdmv1.EnrollRequest{
		EnrollmentToken: token,
		AgentPublicKey: &lmdmv1.HybridPublicKey{
			Ed25519: agentPub.Ed25519,
			MlDsa:   agentPub.MLDSA,
		},
		Hardware:     hardware,
		AgentVersion: agentVersion,
		FirstBoot:    true,
		CsrPem:       csrPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("agentenroll: rpc: %w", err)
	}

	return &Result{
		DeviceID:   resp.GetDeviceId().GetId(),
		SignedCert: resp.GetAgentCertificate(),
		ServerSigningKey: &pqhybrid.SigningPublicKey{
			Ed25519: resp.GetServerSigningKey().GetEd25519(),
			MLDSA:   resp.GetServerSigningKey().GetMlDsa(),
		},
		TenantID:     resp.GetTenantId().GetId(),
		GroupIDs:     resp.GetGroupIds(),
		SiteID:       resp.GetSiteId().GetId(),
		Endpoints:    resp.GetEndpoints(),
		IsRelay:      resp.GetIsRelay(),
		AgentCertPEM: resp.GetAgentCertificatePem(),
		CAPEM:        resp.GetCaCertificatePem(),
	}, nil
}
