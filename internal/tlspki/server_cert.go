// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package tlspki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// DefaultServerCertTTL is the lifetime of the server's TLS cert.
const DefaultServerCertTTL = 5 * 365 * 24 * time.Hour

// ServerCertOptions configures the server cert SANs and CN.
type ServerCertOptions struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	TTL        time.Duration
}

// GenerateServerCert issues a TLS server cert signed by the CA.
// The cert carries both serverAuth and clientAuth ExtKeyUsage so the same
// cert can serve gRPC/REST AND act as the server's own NATS client identity.
func (c *CA) GenerateServerCert(opts ServerCertOptions) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("tlspki: generate server key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultServerCertTTL
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{"LMDM Server"},
		},
		DNSNames:    opts.DNSNames,
		IPAddresses: opts.IPs,
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &priv.PublicKey, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlspki: sign server cert: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("tlspki: marshal server key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
