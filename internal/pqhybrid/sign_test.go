package pqhybrid

import (
	"crypto/rand"
	"testing"
)

func TestGenerateSigningKey(t *testing.T) {
	priv, pub, err := GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	if len(priv.Ed25519) == 0 || len(priv.MLDSA) == 0 {
		t.Fatal("private key must contain both Ed25519 and ML-DSA seeds")
	}
	if len(pub.Ed25519) == 0 || len(pub.MLDSA) == 0 {
		t.Fatal("public key must contain both Ed25519 and ML-DSA bytes")
	}
}

func TestGenerateSigningKeyIsRandom(t *testing.T) {
	priv1, pub1, err := GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := GenerateSigningKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytesEqual(priv1.Ed25519, priv2.Ed25519) || bytesEqual(pub1.Ed25519, pub2.Ed25519) {
		t.Fatal("two generations must not produce identical Ed25519 material")
	}
	if bytesEqual(priv1.MLDSA, priv2.MLDSA) || bytesEqual(pub1.MLDSA, pub2.MLDSA) {
		t.Fatal("two generations must not produce identical ML-DSA material")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
