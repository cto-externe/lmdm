// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package identity signs and verifies the SignedAgentCert envelope used to
// authenticate enrolled agents. Internally, an AgentIdentityCert is marshaled
// to canonical bytes and signed with the server's hybrid signing key.
package identity

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

// SignCert sets issued_at / expires_at on the cert, marshals it with
// deterministic protobuf encoding, signs the result with the server's hybrid
// key, and returns a SignedAgentCert ready to send on the wire.
func SignCert(cert *lmdmv1.AgentIdentityCert, serverPriv *pqhybrid.SigningPrivateKey, ttl time.Duration) (*lmdmv1.SignedAgentCert, error) {
	if cert == nil {
		return nil, errors.New("identity: nil cert")
	}
	now := time.Now()
	cert.IssuedAt = timestamppb.New(now)
	cert.ExpiresAt = timestamppb.New(now.Add(ttl))

	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal cert: %w", err)
	}
	sig, err := pqhybrid.Sign(serverPriv, body)
	if err != nil {
		return nil, fmt.Errorf("identity: sign cert: %w", err)
	}
	return &lmdmv1.SignedAgentCert{
		CertBytes: body,
		Signature: &lmdmv1.HybridSignature{
			Ed25519: sig.Ed25519,
			MlDsa:   sig.MLDSA,
		},
	}, nil
}

// VerifyCert validates the signature using the server's hybrid public key,
// then unmarshals the cert payload and returns it. Callers MUST check
// expiry/scope on the returned cert before trusting it.
func VerifyCert(signed *lmdmv1.SignedAgentCert, serverPub *pqhybrid.SigningPublicKey) (*lmdmv1.AgentIdentityCert, error) {
	if signed == nil || len(signed.CertBytes) == 0 || signed.Signature == nil {
		return nil, errors.New("identity: incomplete signed cert")
	}
	hybridSig := &pqhybrid.HybridSignature{
		Ed25519: signed.Signature.Ed25519,
		MLDSA:   signed.Signature.MlDsa,
	}
	if err := pqhybrid.Verify(serverPub, signed.CertBytes, hybridSig); err != nil {
		return nil, fmt.Errorf("identity: verify: %w", err)
	}
	var cert lmdmv1.AgentIdentityCert
	if err := proto.Unmarshal(signed.CertBytes, &cert); err != nil {
		return nil, fmt.Errorf("identity: unmarshal cert: %w", err)
	}
	return &cert, nil
}
