package identity

import (
	"crypto/rand"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

func mkCert(t *testing.T) *lmdmv1.AgentIdentityCert {
	t.Helper()
	_, agentPub, err := pqhybrid.GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &lmdmv1.AgentIdentityCert{
		DeviceId: &lmdmv1.DeviceID{Id: "dev-1"},
		TenantId: &lmdmv1.TenantID{Id: "00000000-0000-0000-0000-000000000000"},
		AgentPublicKey: &lmdmv1.HybridPublicKey{
			Ed25519: agentPub.Ed25519,
			MlDsa:   agentPub.MLDSA,
		},
		Serial: "abcd",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	serverPriv, serverPub, err := pqhybrid.GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := mkCert(t)
	signed, err := SignCert(cert, serverPriv, time.Hour)
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	got, err := VerifyCert(signed, serverPub)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	if got.GetDeviceId().GetId() != "dev-1" {
		t.Errorf("device id = %q", got.GetDeviceId().GetId())
	}
}

func TestVerifyRejectsTamperedCertBytes(t *testing.T) {
	serverPriv, serverPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	cert := mkCert(t)
	signed, err := SignCert(cert, serverPriv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signed.CertBytes[0] ^= 0x01
	if _, err := VerifyCert(signed, serverPub); err == nil {
		t.Fatal("VerifyCert should reject tampered cert_bytes")
	}
}

func TestVerifyRejectsWrongServerKey(t *testing.T) {
	serverPriv, _, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	_, otherPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	cert := mkCert(t)
	signed, err := SignCert(cert, serverPriv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCert(signed, otherPub); err == nil {
		t.Fatal("VerifyCert should reject signature from wrong server key")
	}
}

func TestSignCertSetsExpiry(t *testing.T) {
	serverPriv, serverPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	cert := mkCert(t)
	signed, err := SignCert(cert, serverPriv, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyCert(signed, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetIssuedAt() == nil || got.GetExpiresAt() == nil {
		t.Fatal("issued_at / expires_at must be set")
	}
	delta := got.GetExpiresAt().AsTime().Sub(got.GetIssuedAt().AsTime())
	if delta < 29*time.Minute || delta > 31*time.Minute {
		t.Errorf("ttl = %v, want ~30m", delta)
	}

	// Sanity: marshaling the same cert produces non-empty bytes (no extra wrapping).
	raw, _ := proto.Marshal(got)
	if len(raw) == 0 {
		t.Fatal("re-marshal produced empty bytes")
	}
}
