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

func TestEncapsulateDecapsulateRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKEMKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct, sharedA, err := Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(sharedA) != SharedSecretSize {
		t.Fatalf("shared secret size = %d, want %d", len(sharedA), SharedSecretSize)
	}
	sharedB, err := Decapsulate(priv, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytesEqual(sharedA, sharedB) {
		t.Fatal("encapsulation and decapsulation must yield identical shared secret")
	}
}

func TestDecapsulateRejectsTamperedCiphertext(t *testing.T) {
	priv, pub, err := GenerateKEMKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct, sharedA, err := Encapsulate(pub)
	if err != nil {
		t.Fatal(err)
	}
	tampered := &HybridCiphertext{
		X25519EphemeralPub: append([]byte{}, ct.X25519EphemeralPub...),
		MLKEMCiphertext:    append([]byte{}, ct.MLKEMCiphertext...),
	}
	tampered.X25519EphemeralPub[0] ^= 0x01

	sharedB, err := Decapsulate(priv, tampered)
	if err != nil {
		return // acceptable: X25519 point invalid or shared derivation fails
	}
	if bytesEqual(sharedA, sharedB) {
		t.Fatal("tampered X25519 ephemeral must not yield the same shared secret")
	}
}

func TestDecapsulateRejectsBadLengths(t *testing.T) {
	priv, _, err := GenerateKEMKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decapsulate(priv, &HybridCiphertext{}); err == nil {
		t.Fatal("Decapsulate should reject empty ciphertext")
	}
	if _, err := Decapsulate(priv, &HybridCiphertext{X25519EphemeralPub: []byte{1, 2}}); err == nil {
		t.Fatal("Decapsulate should reject bad X25519 length")
	}
}

func FuzzDecapsulateNeverPanics(f *testing.F) {
	priv, pub, err := GenerateKEMKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ct, _, err := Encapsulate(pub)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ct.X25519EphemeralPub, ct.MLKEMCiphertext)
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 32), make([]byte, 1088))

	f.Fuzz(func(t *testing.T, x, ml []byte) {
		_, _ = Decapsulate(priv, &HybridCiphertext{X25519EphemeralPub: x, MLKEMCiphertext: ml})
	})
}
