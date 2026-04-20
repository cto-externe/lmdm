// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agenttls manages the agent's X.509 credential lifecycle: keypair
// generation, CSR construction, disk persistence, TLS config building, and
// renewal before expiry.
package agenttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// Keypair bundles an ECDSA P-256 private key with its matching public key.
type Keypair struct {
	Priv *ecdsa.PrivateKey
}

// GenerateKeypair returns a fresh ECDSA P-256 keypair.
func GenerateKeypair() (*Keypair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("agenttls: generate keypair: %w", err)
	}
	return &Keypair{Priv: priv}, nil
}

// MarshalPrivateKeyPEM returns the key in SEC1 EC PEM form (chmod 0600 on disk).
func (k *Keypair) MarshalPrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(k.Priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// BuildCSR constructs a CSR with CommonName = deviceID (UUID string) and
// optional DNS SANs (typically the device hostname for human-readable audit).
func (k *Keypair) BuildCSR(deviceID string, hostname string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{"LMDM Agent"},
		},
	}
	if hostname != "" {
		tpl.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, k.Priv)
	if err != nil {
		return nil, fmt.Errorf("agenttls: create csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
