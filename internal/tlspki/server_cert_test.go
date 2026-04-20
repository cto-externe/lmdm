// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package tlspki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
)

func parseServerCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		t.Fatalf("decode server cert pem")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	return cert
}

func TestGenerateServerCert_IncludesServerAndClientAuth(t *testing.T) {
	ca := newTestCA(t)
	certPEM, keyPEM, err := ca.GenerateServerCert(ServerCertOptions{
		CommonName: "lmdm-server",
		DNSNames:   []string{"lmdm.test"},
	})
	if err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}
	if len(keyPEM) == 0 {
		t.Fatalf("expected key PEM")
	}
	cert := parseServerCert(t, certPEM)

	var foundServerAuth, foundClientAuth bool
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			foundServerAuth = true
		case x509.ExtKeyUsageClientAuth:
			foundClientAuth = true
		}
	}
	if !foundServerAuth {
		t.Fatalf("ExtKeyUsage missing ServerAuth: %v", cert.ExtKeyUsage)
	}
	if !foundClientAuth {
		t.Fatalf("ExtKeyUsage missing ClientAuth: %v", cert.ExtKeyUsage)
	}
}

func TestGenerateServerCert_SANsPopulated(t *testing.T) {
	ca := newTestCA(t)
	wantDNS := []string{"lmdm.test", "localhost"}
	wantIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	certPEM, _, err := ca.GenerateServerCert(ServerCertOptions{
		CommonName: "lmdm-server",
		DNSNames:   wantDNS,
		IPs:        wantIPs,
	})
	if err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}
	cert := parseServerCert(t, certPEM)

	for _, want := range wantDNS {
		found := false
		for _, got := range cert.DNSNames {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("DNSNames missing %q: got %v", want, cert.DNSNames)
		}
	}
	for _, want := range wantIPs {
		found := false
		for _, got := range cert.IPAddresses {
			if got.Equal(want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("IPAddresses missing %s: got %v", want, cert.IPAddresses)
		}
	}
}

func TestGenerateServerCert_SignedByCA(t *testing.T) {
	ca := newTestCA(t)
	certPEM, _, err := ca.GenerateServerCert(ServerCertOptions{
		CommonName: "lmdm-server",
		DNSNames:   []string{"lmdm.test"},
	})
	if err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}
	cert := parseServerCert(t, certPEM)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:   pool,
		DNSName: "lmdm.test",
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
}
