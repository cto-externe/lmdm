// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package tlspki provides PKI operations for LMDM: generating the CA,
// signing CSRs to produce agent X.509 certificates, issuing the server's
// TLS cert, and caching revoked serials for the VerifyPeerCertificate
// callback.
package tlspki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// DefaultCATTL is the lifetime of a newly generated CA.
const DefaultCATTL = 10 * 365 * 24 * time.Hour

// GenerateCA creates a fresh CA keypair + self-signed cert valid for DefaultCATTL.
// Returns (certPEM, keyPEM). Caller writes to disk at chmod 0600 (key) / 0644 (cert).
func GenerateCA(commonName string) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlspki: generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"LMDM"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(DefaultCATTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("tlspki: sign CA: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("tlspki: marshal CA key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// CA holds a parsed CA certificate + private key for signing end-entity certs.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// LoadCA reads the CA cert + key PEM files from disk.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // path is an explicit configuration input
	if err != nil {
		return nil, fmt.Errorf("tlspki: read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // path is an explicit configuration input
	if err != nil {
		return nil, fmt.Errorf("tlspki: read ca key: %w", err)
	}
	return parseCA(certPEM, keyPEM)
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("tlspki: ca cert pem decode failed")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlspki: parse ca cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("tlspki: ca key pem decode failed")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		k, err2 := x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("tlspki: parse ca key: %w", err)
		}
		eck, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("tlspki: ca key is not ECDSA")
		}
		key = eck
	}
	if !cert.IsCA {
		return nil, errors.New("tlspki: cert is not a CA (IsCA=false)")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// DefaultAgentCertTTL mirrors cfg.EnrollmentCertTTL default.
const DefaultAgentCertTTL = 365 * 24 * time.Hour

// SignCSR validates the CSR (signature check) and issues an X.509 certificate
// signed by the CA. The cert's SerialNumber is random 128-bit. CommonName
// must be supplied by the caller (typically the device UUID). SAN DNS names
// may be populated from the request if the CSR carried them.
func (c *CA) SignCSR(csr *x509.CertificateRequest, commonName string, ttl time.Duration) ([]byte, error) {
	if csr == nil {
		return nil, errors.New("tlspki: nil csr")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("tlspki: csr signature: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultAgentCertTTL
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"LMDM Agent"},
		},
		DNSNames:    csr.DNSNames,
		IPAddresses: csr.IPAddresses,
		NotBefore:   time.Now().Add(-1 * time.Minute),
		NotAfter:    time.Now().Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, csr.PublicKey, c.Key)
	if err != nil {
		return nil, fmt.Errorf("tlspki: sign csr: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
