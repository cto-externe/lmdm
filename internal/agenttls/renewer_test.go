// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenttls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/cto-externe/lmdm/internal/tlspki"
)

type fakeRenewClient struct {
	ca       *tlspki.CA
	deviceID string
	ttl      time.Duration
	calls    int
	err      error
}

func (f *fakeRenewClient) RenewCertificate(_ context.Context, csrPEM []byte) ([]byte, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("fake: decode csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	ttl := f.ttl
	if ttl == 0 {
		ttl = 365 * 24 * time.Hour
	}
	return f.ca.SignCSR(csr, f.deviceID, ttl)
}

// newTestCA builds a fresh in-memory CA for tests.
func newTestCA(t *testing.T) *tlspki.CA {
	t.Helper()
	certPEM, keyPEM, err := tlspki.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	// parseCA is unexported; reconstruct via temp files + LoadCA.
	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	if err := writeFile(certPath, certPEM); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(keyPath, keyPEM); err != nil {
		t.Fatal(err)
	}
	ca, err := tlspki.LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return ca
}

func writeFile(path string, data []byte) error {
	return writeAtomic(path, data, 0o600)
}

// seedAgentCert generates an ephemeral keypair for deviceID, signs it with ca
// using the given ttl, and writes cert+key+ca into store.
func seedAgentCert(t *testing.T, store *Store, ca *tlspki.CA, deviceID string, ttl time.Duration) (certPEM, keyPEM []byte) {
	t.Helper()
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	csrPEM, err := kp.BuildCSR(deviceID, "test-host")
	if err != nil {
		t.Fatalf("BuildCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("decode csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	certPEM, err = ca.SignCSR(csr, deviceID, ttl)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	keyPEM, err = kp.MarshalPrivateKeyPEM()
	if err != nil {
		t.Fatalf("MarshalPrivateKeyPEM: %v", err)
	}
	caPEM := encodeCACertPEM(t, ca)
	if err := store.SaveCredentials(certPEM, keyPEM, caPEM); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}
	return certPEM, keyPEM
}

func encodeCACertPEM(t *testing.T, ca *tlspki.CA) []byte {
	t.Helper()
	// Re-encode the parsed CA cert back to PEM for the store.
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

func loadCertNotAfter(t *testing.T, certPEM []byte) time.Time {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("decode cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert.NotAfter
}

func TestRunner_FreshCert_SkipsRenew(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ca := newTestCA(t)
	origCert, origKey := seedAgentCert(t, store, ca, "test-device", 200*24*time.Hour)

	fc := &fakeRenewClient{ca: ca, deviceID: "test-device"}
	runner := NewRunner(store, fc, "test-device", "test-host")
	runner.tryRenewOnce(context.Background())

	if fc.calls != 0 {
		t.Fatalf("expected 0 renew calls, got %d", fc.calls)
	}
	gotCert, gotKey, _, err := store.LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if !bytes.Equal(gotCert, origCert) {
		t.Fatalf("cert changed unexpectedly")
	}
	if !bytes.Equal(gotKey, origKey) {
		t.Fatalf("key changed unexpectedly")
	}
	if !loadCertNotAfter(t, gotCert).Equal(loadCertNotAfter(t, origCert)) {
		t.Fatalf("NotAfter changed unexpectedly")
	}
}

func TestRunner_ExpiredSoon_Renews(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ca := newTestCA(t)
	origCert, origKey := seedAgentCert(t, store, ca, "test-device", 10*24*time.Hour)

	fc := &fakeRenewClient{ca: ca, deviceID: "test-device", ttl: 365 * 24 * time.Hour}
	runner := NewRunner(store, fc, "test-device", "test-host")
	runner.tryRenewOnce(context.Background())

	if fc.calls != 1 {
		t.Fatalf("expected 1 renew call, got %d", fc.calls)
	}
	newCert, newKey, _, err := store.LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if bytes.Equal(newCert, origCert) {
		t.Fatalf("cert unchanged after renewal")
	}
	if bytes.Equal(newKey, origKey) {
		t.Fatalf("key unchanged after renewal")
	}
	origNotAfter := loadCertNotAfter(t, origCert)
	newNotAfter := loadCertNotAfter(t, newCert)
	if !newNotAfter.After(origNotAfter) {
		t.Fatalf("new cert NotAfter %v not after original %v", newNotAfter, origNotAfter)
	}
}

func TestRunner_RenewRPCFails_StoreUntouched(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ca := newTestCA(t)
	origCert, origKey := seedAgentCert(t, store, ca, "test-device", 10*24*time.Hour)

	fc := &fakeRenewClient{ca: ca, deviceID: "test-device", err: errors.New("rpc fail")}
	runner := NewRunner(store, fc, "test-device", "test-host")
	runner.tryRenewOnce(context.Background())

	if fc.calls != 1 {
		t.Fatalf("expected 1 renew call, got %d", fc.calls)
	}
	gotCert, gotKey, _, err := store.LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if !bytes.Equal(gotCert, origCert) {
		t.Fatalf("cert changed despite failed renewal")
	}
	if !bytes.Equal(gotKey, origKey) {
		t.Fatalf("key changed despite failed renewal")
	}
}

func TestRunner_NoCredentials_NoOp(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ca := newTestCA(t)

	fc := &fakeRenewClient{ca: ca, deviceID: "test-device"}
	runner := NewRunner(store, fc, "test-device", "test-host")

	// Must not panic even with empty store.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("tryRenewOnce panicked: %v", r)
		}
	}()
	runner.tryRenewOnce(context.Background())

	if fc.calls != 0 {
		t.Fatalf("expected 0 renew calls, got %d", fc.calls)
	}
}
