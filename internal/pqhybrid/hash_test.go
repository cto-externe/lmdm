package pqhybrid

import (
	"encoding/hex"
	"testing"
)

func TestHashEmpty(t *testing.T) {
	// Vecteur BLAKE3 officiel pour input vide.
	got := hex.EncodeToString(Hash(nil))
	want := "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	if got != want {
		t.Fatalf("Hash(nil) = %s, want %s", got, want)
	}
}

func TestHashKnownInput(t *testing.T) {
	// Vecteur BLAKE3 officiel pour l'input "IETF".
	got := hex.EncodeToString(Hash([]byte("IETF")))
	want := "83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2"
	if got != want {
		t.Fatalf("Hash(\"IETF\") = %s, want %s", got, want)
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	payload := []byte("hello lmdm")
	digest := Hash(payload)
	if !VerifyHash(payload, digest) {
		t.Fatal("VerifyHash should succeed on untampered payload")
	}
	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0x01
	if VerifyHash(tampered, digest) {
		t.Fatal("VerifyHash should fail on tampered payload")
	}
}
