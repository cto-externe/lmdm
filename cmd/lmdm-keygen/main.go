// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// lmdm-keygen generates the JWT ECDSA P-256 keypair (used by internal/auth.JWTSigner),
// the AES-256 master key (used by internal/auth.Encrypt/Decrypt for TOTP secrets),
// the LMDM Root CA, and the server TLS certificate signed by that CA.
//
// Output files (written to --out, default "."):
//
//	ca.crt         LMDM Root CA certificate, PEM, chmod 0644 (distribute to agents)
//	ca.key         LMDM Root CA private key, PEM, chmod 0600 (server-only)
//	server.crt     Server TLS certificate signed by the CA, chmod 0644
//	server.key     Server TLS private key, chmod 0600
//	jwt-priv.pem   ECDSA P-256 JWT private key, PEM-encoded, chmod 0600
//	jwt-pub.pem    corresponding JWT public key, chmod 0644 (for future JWKS)
//	enc-key.b64    32-byte random AES master key, base64 + trailing newline, chmod 0600
//
// Once written, export the LMDM_* path env vars printed at the end so the server
// can load its secrets at boot.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cto-externe/lmdm/internal/tlspki"
)

// stringSlice implements flag.Value for repeatable string flags.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	out := flag.String("out", ".", "directory to write keys into")
	serverCN := flag.String("server-cn", "lmdm-server", "common name for the server TLS certificate")
	var dnsNames stringSlice
	flag.Var(&dnsNames, "server-dns", "DNS SAN for server cert (repeatable, default: localhost)")
	var ipStrs stringSlice
	flag.Var(&ipStrs, "server-ip", "IP SAN for server cert (repeatable, default: 127.0.0.1, ::1)")
	flag.Parse()

	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}
	ips := make([]net.IP, 0, len(ipStrs))
	for _, s := range ipStrs {
		ip := net.ParseIP(s)
		if ip == nil {
			fail("invalid IP: " + s)
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		ips = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}

	if err := os.MkdirAll(*out, 0o700); err != nil {
		fail("mkdir: " + err.Error())
	}

	// ECDSA P-256 keypair for JWT signing
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	privDER, err := x509.MarshalECPrivateKey(priv)
	must(err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	must(writeFile(filepath.Join(*out, "jwt-priv.pem"), privPEM, 0o600))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	must(err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	must(writeFile(filepath.Join(*out, "jwt-pub.pem"), pubPEM, 0o644))

	// AES-256 master key, base64-encoded
	encKey := make([]byte, 32)
	_, err = rand.Read(encKey)
	must(err)
	b64 := base64.StdEncoding.EncodeToString(encKey) + "\n"
	must(writeFile(filepath.Join(*out, "enc-key.b64"), []byte(b64), 0o600))

	// LMDM Root CA
	caCertPEM, caKeyPEM, err := tlspki.GenerateCA("LMDM Root CA")
	must(err)
	caCertPath := filepath.Join(*out, "ca.crt")
	caKeyPath := filepath.Join(*out, "ca.key")
	must(writeFile(caCertPath, caCertPEM, 0o644))
	must(writeFile(caKeyPath, caKeyPEM, 0o600))

	// Reload CA so we have a *tlspki.CA for signing.
	ca, err := tlspki.LoadCA(caCertPath, caKeyPath)
	must(err)

	// Server TLS certificate signed by the CA.
	serverCertPEM, serverKeyPEM, err := ca.GenerateServerCert(tlspki.ServerCertOptions{
		CommonName: *serverCN,
		DNSNames:   []string(dnsNames),
		IPs:        ips,
	})
	must(err)
	must(writeFile(filepath.Join(*out, "server.crt"), serverCertPEM, 0o644))
	must(writeFile(filepath.Join(*out, "server.key"), serverKeyPEM, 0o600))

	fmt.Println("Wrote:")
	fmt.Println("  ca.crt        (CA certificate, chmod 0644 \u2014 distribute to agents)")
	fmt.Println("  ca.key        (CA private key, chmod 0600 \u2014 server-only, NEVER expose)")
	fmt.Println("  server.crt    (server TLS certificate, chmod 0644)")
	fmt.Println("  server.key    (server TLS private key, chmod 0600)")
	fmt.Println("  jwt-priv.pem  (ECDSA P-256 JWT private key, chmod 0600)")
	fmt.Println("  jwt-pub.pem   (JWT public key, chmod 0644)")
	fmt.Println("  enc-key.b64   (AES-256 master key, base64, chmod 0600)")
	fmt.Println()
	fmt.Println("Export (or mount as secrets):")
	fmt.Printf("  LMDM_CA_CERT_PATH=%s\n", caCertPath)
	fmt.Printf("  LMDM_CA_KEY_PATH=%s\n", caKeyPath)
	fmt.Printf("  LMDM_SERVER_CERT_PATH=%s\n", filepath.Join(*out, "server.crt"))
	fmt.Printf("  LMDM_SERVER_KEY_PATH=%s\n", filepath.Join(*out, "server.key"))
	fmt.Printf("  LMDM_JWT_PRIVATE_KEY_PATH=%s\n", filepath.Join(*out, "jwt-priv.pem"))
	fmt.Printf("  LMDM_ENC_KEY_PATH=%s\n", filepath.Join(*out, "enc-key.b64"))
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "lmdm-keygen:", msg)
	os.Exit(1)
}
