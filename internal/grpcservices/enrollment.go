// Package grpcservices implements the gRPC service handlers for LMDM.
// Currently only EnrollmentService is implemented.
package grpcservices

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/identity"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
	"github.com/cto-externe/lmdm/internal/tokens"
)

// EnrollmentService implements lmdmv1.EnrollmentServiceServer.
type EnrollmentService struct {
	lmdmv1.UnimplementedEnrollmentServiceServer

	tokens     *tokens.Repository
	devices    *devices.Repository
	serverPriv *pqhybrid.SigningPrivateKey
	serverPub  *pqhybrid.SigningPublicKey
	endpoints  *lmdmv1.ServerEndpoints
	certTTL    time.Duration
}

// NewEnrollmentService wires the dependencies needed by the Enroll handler.
func NewEnrollmentService(
	tokenRepo *tokens.Repository,
	deviceRepo *devices.Repository,
	serverPriv *pqhybrid.SigningPrivateKey,
	serverPub *pqhybrid.SigningPublicKey,
	endpoints *lmdmv1.ServerEndpoints,
	certTTL time.Duration,
) *EnrollmentService {
	return &EnrollmentService{
		tokens:     tokenRepo,
		devices:    deviceRepo,
		serverPriv: serverPriv,
		serverPub:  serverPub,
		endpoints:  endpoints,
		certTTL:    certTTL,
	}
}

// Enroll consumes the supplied token, persists a device row, signs an
// AgentIdentityCert, and returns the cert + endpoints to the agent.
func (s *EnrollmentService) Enroll(ctx context.Context, req *lmdmv1.EnrollRequest) (*lmdmv1.EnrollResponse, error) {
	if req.GetEnrollmentToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "enrollment_token required")
	}
	if req.GetAgentPublicKey() == nil ||
		len(req.GetAgentPublicKey().GetEd25519()) == 0 ||
		len(req.GetAgentPublicKey().GetMlDsa()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "agent_public_key incomplete")
	}
	if req.GetHardware().GetHostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "hardware.hostname required")
	}

	tok, err := s.tokens.ValidateAndConsume(ctx, req.GetEnrollmentToken())
	if err != nil {
		if errors.Is(err, tokens.ErrTokenInvalid) {
			return nil, status.Error(codes.PermissionDenied, "token invalid or expired")
		}
		return nil, status.Errorf(codes.Internal, "token validation: %v", err)
	}

	deviceID, err := uuid.NewV7()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "uuid: %v", err)
	}
	serial := uuid.NewString()

	d := &devices.Device{
		ID:                 deviceID,
		TenantID:           tok.TenantID,
		Type:               devices.TypeWorkstation,
		Hostname:           req.GetHardware().GetHostname(),
		SerialNumber:       strPtr(req.GetHardware().GetSerialNumber()),
		Manufacturer:       strPtr(req.GetHardware().GetManufacturer()),
		Model:              strPtr(req.GetHardware().GetModel()),
		SiteID:             tok.SiteID,
		EnrolledViaToken:   &tok.ID,
		AgentPubkeyEd25519: req.GetAgentPublicKey().GetEd25519(),
		AgentPubkeyMLDSA:   req.GetAgentPublicKey().GetMlDsa(),
		CertSerial:         &serial,
	}
	if err := s.devices.Insert(ctx, d); err != nil {
		return nil, status.Errorf(codes.Internal, "device insert: %v", err)
	}

	cert := &lmdmv1.AgentIdentityCert{
		DeviceId:       &lmdmv1.DeviceID{Id: deviceID.String()},
		TenantId:       &lmdmv1.TenantID{Id: tok.TenantID.String()},
		GroupIds:       tok.GroupIDs,
		AgentPublicKey: req.GetAgentPublicKey(),
		Serial:         serial,
	}
	if tok.SiteID != nil {
		cert.SiteId = &lmdmv1.SiteID{Id: tok.SiteID.String()}
	}

	signed, err := identity.SignCert(cert, s.serverPriv, s.certTTL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign cert: %v", err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal signed cert: %v", err)
	}

	resp := &lmdmv1.EnrollResponse{
		DeviceId:         &lmdmv1.DeviceID{Id: deviceID.String()},
		AgentCertificate: signedBytes,
		ServerSigningKey: &lmdmv1.HybridPublicKey{
			Ed25519: s.serverPub.Ed25519,
			MlDsa:   s.serverPub.MLDSA,
		},
		TenantId:  &lmdmv1.TenantID{Id: tok.TenantID.String()},
		GroupIds:  tok.GroupIDs,
		Endpoints: s.endpoints,
	}
	if tok.SiteID != nil {
		resp.SiteId = &lmdmv1.SiteID{Id: tok.SiteID.String()}
	}
	return resp, nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Compile-time interface assertion.
var _ lmdmv1.EnrollmentServiceServer = (*EnrollmentService)(nil)
