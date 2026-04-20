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
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestGenerateCA_RoundTripParsesCleanly(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("LMDM Test CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	writeFile(t, certPath, certPEM, 0o644)
	writeFile(t, keyPath, keyPEM, 0o600)

	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !ca.Cert.IsCA {
		t.Fatalf("expected IsCA=true")
	}
	wantNotAfter := time.Now().Add(DefaultCATTL)
	delta := ca.Cert.NotAfter.Sub(wantNotAfter)
	if delta < -1*time.Hour || delta > 1*time.Hour {
		t.Fatalf("NotAfter not ~10y away (delta=%s)", delta)
	}
	if ca.Cert.Subject.CommonName != "LMDM Test CA" {
		t.Fatalf("unexpected CN: %q", ca.Cert.Subject.CommonName)
	}
}

func TestLoadCA_PKCS8Key_Accepted(t *testing.T) {
	// Generate a CA cert with a key, then re-encode the key as PKCS8.
	certPEM, keyPEM, err := GenerateCA("LMDM PKCS8 CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		t.Fatalf("decode original key")
	}
	ecKey, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatalf("parse ec key: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	writeFile(t, certPath, certPEM, 0o644)
	writeFile(t, keyPath, pkcs8PEM, 0o600)

	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA pkcs8: %v", err)
	}
	if ca.Key == nil {
		t.Fatalf("nil key")
	}
}

func TestLoadCA_NonCA_Rejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "not-a-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "x.crt")
	keyPath := filepath.Join(dir, "x.key")
	writeFile(t, certPath, certPEM, 0o644)
	writeFile(t, keyPath, keyPEM, 0o600)

	_, err = LoadCA(certPath, keyPath)
	if err == nil {
		t.Fatalf("expected error for non-CA cert")
	}
	if !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("expected 'not a CA' error, got: %v", err)
	}
}

func makeCSR(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return der, priv
}

func newTestCA(t *testing.T) *CA {
	t.Helper()
	certPEM, keyPEM, err := GenerateCA("LMDM Sign CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ca, err := parseCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCA: %v", err)
	}
	return ca
}

func TestSignCSR_RejectsInvalidSignature(t *testing.T) {
	ca := newTestCA(t)
	csrDER, _ := makeCSR(t, "tampered-device")

	// Mutate one byte in the signature region (last bytes of DER).
	mutated := make([]byte, len(csrDER))
	copy(mutated, csrDER)
	mutated[len(mutated)-5] ^= 0xFF

	csr, err := x509.ParseCertificateRequest(mutated)
	if err != nil {
		// If parsing alone catches the corruption, that is also acceptable
		// proof we never sign garbage. Make sure SignCSR also rejects when
		// passed the parsed-but-invalid CSR (re-parse the original first
		// then mutate the parsed sig bytes).
		csr, perr := x509.ParseCertificateRequest(csrDER)
		if perr != nil {
			t.Fatalf("parse original csr: %v", perr)
		}
		csr.Signature[len(csr.Signature)-1] ^= 0xFF
		if _, sErr := ca.SignCSR(csr, "tampered-device", 0); sErr == nil {
			t.Fatalf("expected SignCSR to reject mutated signature")
		}
		return
	}
	if _, err := ca.SignCSR(csr, "tampered-device", 0); err == nil {
		t.Fatalf("expected SignCSR to reject mutated CSR")
	}
}

func TestSignCSR_ValidCSR_IssuesClientAuthCert(t *testing.T) {
	ca := newTestCA(t)
	csrDER, _ := makeCSR(t, "test-device")
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}

	certPEM, err := ca.SignCSR(csr, "test-device", 0)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		t.Fatalf("decode signed cert")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}

	if cert.Subject.CommonName != "test-device" {
		t.Fatalf("unexpected CN: %q", cert.Subject.CommonName)
	}
	foundClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
			break
		}
	}
	if !foundClientAuth {
		t.Fatalf("ExtKeyUsage missing ClientAuth: %v", cert.ExtKeyUsage)
	}

	// Verify chain.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
}
