package pqhybrid

import (
	"crypto/rand"
	"testing"
)

func TestGenerateKEMKey(t *testing.T) {
	priv, pub, err := GenerateKEMKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKEMKey: %v", err)
	}
	if priv.X25519 == nil || priv.MLKEM == nil {
		t.Fatal("private key must contain both X25519 and ML-KEM material")
	}
	if len(pub.X25519) == 0 || len(pub.MLKEM) == 0 {
		t.Fatal("public key must contain both X25519 and ML-KEM material")
	}
}

func TestGenerateKEMKeyIsRandom(t *testing.T) {
	_, pub1, err := GenerateKEMKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, pub2, err := GenerateKEMKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytesEqual(pub1.X25519, pub2.X25519) {
		t.Fatal("two generations must not produce identical X25519 public keys")
	}
	if bytesEqual(pub1.MLKEM, pub2.MLKEM) {
		t.Fatal("two generations must not produce identical ML-KEM public keys")
	}
}
