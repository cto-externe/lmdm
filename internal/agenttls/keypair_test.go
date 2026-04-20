// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenttls

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenerateKeypair_ProducesP256(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if kp.Priv == nil {
		t.Fatal("GenerateKeypair: Priv is nil")
	}
	if kp.Priv.Curve != elliptic.P256() {
		t.Fatalf("expected P-256 curve, got %v", kp.Priv.Curve)
	}
}

func TestBuildCSR_ParsesBackAndVerifies(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	const deviceID = "550e8400-e29b-41d4-a716-446655440000"
	csrPEM, err := kp.BuildCSR(deviceID, "")
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("pem.Decode: nil block")
	}
	if len(rest) != 0 {
		t.Fatalf("pem.Decode: trailing bytes: %d", len(rest))
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("unexpected PEM type: %s", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	if csr.Subject.CommonName != deviceID {
		t.Fatalf("CommonName = %q, want %q", csr.Subject.CommonName, deviceID)
	}
	if len(csr.DNSNames) != 0 {
		t.Fatalf("DNSNames = %v, want empty", csr.DNSNames)
	}
}

func TestBuildCSR_IncludesDNSSAN(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	const deviceID = "550e8400-e29b-41d4-a716-446655440000"
	const hostname = "workstation-01"
	csrPEM, err := kp.BuildCSR(deviceID, hostname)
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("pem.Decode: nil block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != hostname {
		t.Fatalf("DNSNames = %v, want [%q]", csr.DNSNames, hostname)
	}
}
