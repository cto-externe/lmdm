// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenttls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cto-externe/lmdm/internal/tlspki"
)

func mustBuildFixtures(t *testing.T) (agentCertPEM, agentKeyPEM, caCertPEM []byte) {
	t.Helper()

	caCertPEM, caKeyPEM, err := tlspki.GenerateCA("test CA")
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	dir := t.TempDir()
	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(caCertPath, caCertPEM, 0o644); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	if err := os.WriteFile(caKeyPath, caKeyPEM, 0o600); err != nil {
		t.Fatalf("write ca key: %v", err)
	}
	ca, err := tlspki.LoadCA(caCertPath, caKeyPath)
	if err != nil {
		t.Fatalf("load CA: %v", err)
	}

	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	csrPEM, err := kp.BuildCSR("test-device", "")
	if err != nil {
		t.Fatalf("build csr: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("decode csr PEM: nil block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	certPEM, err := ca.SignCSR(csr, "test-device", 0)
	if err != nil {
		t.Fatalf("sign csr: %v", err)
	}
	keyPEM, err := kp.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return certPEM, keyPEM, caCertPEM
}

func TestBuildClientTLSConfig_HappyPath(t *testing.T) {
	certPEM, keyPEM, caPEM := mustBuildFixtures(t)

	cfg, err := BuildClientTLSConfig(certPEM, keyPEM, caPEM, "lmdm.test")
	if err != nil {
		t.Fatalf("BuildClientTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("config nil")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3 (%x)", cfg.MinVersion, tls.VersionTLS13)
	}
	if len(cfg.CurvePreferences) == 0 {
		t.Fatal("CurvePreferences empty")
	}
	if cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Errorf("CurvePreferences[0] = %v, want X25519MLKEM768", cfg.CurvePreferences[0])
	}
	hasX25519 := false
	hasP256 := false
	for _, c := range cfg.CurvePreferences {
		switch c {
		case tls.X25519:
			hasX25519 = true
		case tls.CurveP256:
			hasP256 = true
		}
	}
	if !hasX25519 {
		t.Error("CurvePreferences missing X25519 fallback")
	}
	if !hasP256 {
		t.Error("CurvePreferences missing CurveP256 fallback")
	}
	if cfg.ServerName != "lmdm.test" {
		t.Errorf("ServerName = %q, want lmdm.test", cfg.ServerName)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("len(Certificates) = %d, want 1", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs nil")
	}
}

func TestBuildClientTLSConfig_BadKeyPair_Errors(t *testing.T) {
	certPEM, _, caPEM := mustBuildFixtures(t)
	// Build a fresh unrelated keypair and use its private key: it will not
	// match the public key baked into certPEM.
	otherKP, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate other keypair: %v", err)
	}
	otherKeyPEM, err := otherKP.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("marshal other key: %v", err)
	}

	_, err = BuildClientTLSConfig(certPEM, otherKeyPEM, caPEM, "lmdm.test")
	if err == nil {
		t.Fatal("expected error for mismatched cert/key pair, got nil")
	}
	if !strings.Contains(err.Error(), "load client cert") {
		t.Errorf("error = %q, want substring 'load client cert'", err.Error())
	}
}

func TestBuildClientTLSConfig_EmptyCAPool_Errors(t *testing.T) {
	certPEM, keyPEM, _ := mustBuildFixtures(t)

	_, err := BuildClientTLSConfig(certPEM, keyPEM, []byte{}, "lmdm.test")
	if err == nil {
		t.Fatal("expected error for empty CA pool, got nil")
	}
	if !strings.Contains(err.Error(), "empty or invalid CA pool") {
		t.Errorf("error = %q, want substring 'empty or invalid CA pool'", err.Error())
	}
}
