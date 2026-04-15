// Package agentenroll wraps the gRPC EnrollmentService.Enroll call into a
// transport-only helper. It does not persist anything — the caller decides
// where to store the returned cert and server pubkey.
package agentenroll

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
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
}

// Enroll connects to the gRPC server, calls EnrollmentService.Enroll with the
// supplied token + agent pubkey + hardware fingerprint, and returns the
// parsed result. Insecure transport at MVP — TLS is added in a later plan.
func Enroll(
	ctx context.Context,
	grpcAddr, token, agentVersion string,
	agentPub *pqhybrid.SigningPublicKey,
	hardware *lmdmv1.HardwareFingerprint,
) (*Result, error) {
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
		TenantID:  resp.GetTenantId().GetId(),
		GroupIDs:  resp.GetGroupIds(),
		SiteID:    resp.GetSiteId().GetId(),
		Endpoints: resp.GetEndpoints(),
		IsRelay:   resp.GetIsRelay(),
	}, nil
}
