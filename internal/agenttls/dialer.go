// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenttls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// BuildClientTLSConfig assembles a *tls.Config for mTLS client connections
// (gRPC + NATS). Uses TLS 1.3 and prefers X25519MLKEM768 (post-quantum hybrid
// key exchange) when both sides support it, with classical fallbacks.
//
// serverName is used for SNI + server cert verification. The caller passes
// the hostname configured on the server's cert (typically from
// ServerCertOptions.DNSNames).
func BuildClientTLSConfig(certPEM, keyPEM, caPEM []byte, serverName string) (*tls.Config, error) {
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("agenttls: load client cert: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("agenttls: empty or invalid CA pool")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
	}, nil
}
