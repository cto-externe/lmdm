// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package grpcservices implements the gRPC service handlers for LMDM.
// Currently only EnrollmentService is implemented.
package grpcservices

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/identity"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
	"github.com/cto-externe/lmdm/internal/tlspki"
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
	ca         *tlspki.CA
}

// NewEnrollmentService wires the dependencies needed by the Enroll handler.
// The ca argument may be nil during bootstrap (Task 15 wires it in
// cmd/lmdm-server/main.go); when nil, the X.509 signing path is skipped and
// RenewCertificate returns codes.Unavailable.
func NewEnrollmentService(
	tokenRepo *tokens.Repository,
	deviceRepo *devices.Repository,
	serverPriv *pqhybrid.SigningPrivateKey,
	serverPub *pqhybrid.SigningPublicKey,
	endpoints *lmdmv1.ServerEndpoints,
	certTTL time.Duration,
	ca *tlspki.CA,
) *EnrollmentService {
	return &EnrollmentService{
		tokens:     tokenRepo,
		devices:    deviceRepo,
		serverPriv: serverPriv,
		serverPub:  serverPub,
		endpoints:  endpoints,
		certTTL:    certTTL,
		ca:         ca,
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

	// X.509 path — sign the CSR if the agent supplied one and the CA is wired.
	// Defense-in-depth: the SignedAgentCert proto above is still returned
	// unconditionally so legacy agents keep working during the transition.
	var x509CertPEM []byte
	var caCertPEM []byte
	if s.ca != nil && len(req.GetCsrPem()) > 0 {
		block, _ := pem.Decode(req.GetCsrPem())
		if block == nil {
			return nil, status.Error(codes.InvalidArgument, "csr_pem decode failed")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "csr parse: %v", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "csr signature: %v", err)
		}
		certPEM, err := s.ca.SignCSR(csr, deviceID.String(), s.certTTL)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "sign csr: %v", err)
		}
		x509CertPEM = certPEM

		// Extract serial from the freshly issued cert for the devices row.
		certBlock, _ := pem.Decode(certPEM)
		if certBlock != nil {
			if issued, perr := x509.ParseCertificate(certBlock.Bytes); perr == nil {
				if err := s.devices.SetCurrentCertSerial(ctx, tok.TenantID, deviceID, issued.SerialNumber.String()); err != nil {
					// Non-fatal; enrollment already succeeded.
					slog.Warn("enrollment: SetCurrentCertSerial failed", "err", err, "device_id", deviceID.String())
				}
			}
		}

		// Include the CA cert so the agent can trust the server-side TLS chain.
		caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.ca.Cert.Raw})
	}

	resp := &lmdmv1.EnrollResponse{
		DeviceId:         &lmdmv1.DeviceID{Id: deviceID.String()},
		AgentCertificate: signedBytes,
		ServerSigningKey: &lmdmv1.HybridPublicKey{
			Ed25519: s.serverPub.Ed25519,
			MlDsa:   s.serverPub.MLDSA,
		},
		TenantId:            &lmdmv1.TenantID{Id: tok.TenantID.String()},
		GroupIds:            tok.GroupIDs,
		Endpoints:           s.endpoints,
		AgentCertificatePem: x509CertPEM,
		CaCertificatePem:    caCertPEM,
	}
	if tok.SiteID != nil {
		resp.SiteId = &lmdmv1.SiteID{Id: tok.SiteID.String()}
	}
	return resp, nil
}

// RenewCertificate issues a fresh X.509 cert for an already-enrolled agent.
// The caller must be authenticated via mTLS; the CSR's CN must match the
// mTLS peer CN to prevent an agent from renewing a cert for a different
// device UUID.
func (s *EnrollmentService) RenewCertificate(ctx context.Context, req *lmdmv1.RenewCertificateRequest) (*lmdmv1.RenewCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.Unavailable, "pki not configured")
	}
	if len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr_pem required")
	}

	peerCert, ok := peerFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no mtls peer")
	}
	authDeviceID := peerCert.Subject.CommonName

	block, _ := pem.Decode(req.GetCsrPem())
	if block == nil {
		return nil, status.Error(codes.InvalidArgument, "csr_pem decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "csr parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "csr signature: %v", err)
	}
	if csr.Subject.CommonName != authDeviceID {
		return nil, status.Error(codes.PermissionDenied, "csr CN does not match mTLS peer CN")
	}

	newCert, err := s.ca.SignCSR(csr, authDeviceID, s.certTTL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign csr: %v", err)
	}

	// Best-effort: update current_cert_serial for the device. We trust the
	// mTLS-validated CN as the device UUID and look up its tenant.
	if devID, perr := uuid.Parse(authDeviceID); perr == nil {
		if tenantID, terr := s.devices.FindTenantForDevice(ctx, devID); terr == nil {
			if certBlock, _ := pem.Decode(newCert); certBlock != nil {
				if issued, ierr := x509.ParseCertificate(certBlock.Bytes); ierr == nil {
					if err := s.devices.SetCurrentCertSerial(ctx, tenantID, devID, issued.SerialNumber.String()); err != nil {
						slog.Warn("renew: SetCurrentCertSerial failed", "err", err, "device_id", devID.String())
					}
				}
			}
		}
	}

	return &lmdmv1.RenewCertificateResponse{
		NewCertificate: newCert,
	}, nil
}

// peerFromContext extracts the leaf certificate from the gRPC mTLS peer
// attached to ctx. Returns (nil, false) when there is no peer or no
// verified chain (i.e. the caller was not authenticated with mTLS).
func peerFromContext(ctx context.Context) (*x509.Certificate, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, false
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, false
	}
	return tlsInfo.State.VerifiedChains[0][0], true
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Compile-time interface assertion.
var _ lmdmv1.EnrollmentServiceServer = (*EnrollmentService)(nil)
