package tokens

import (
	"strings"
	"testing"
)

func TestGenerateProducesUniqueTokens(t *testing.T) {
	plaintext1, hash1, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	plaintext2, hash2, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if plaintext1 == plaintext2 {
		t.Fatal("two calls must yield different plaintexts")
	}
	if string(hash1) == string(hash2) {
		t.Fatal("two calls must yield different hashes")
	}
}

func TestGeneratePlaintextFormat(t *testing.T) {
	plaintext, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Base32-no-padding of 32 bytes = 52 characters.
	if len(plaintext) != 52 {
		t.Fatalf("plaintext length = %d, want 52", len(plaintext))
	}
	if strings.ContainsAny(plaintext, "=") {
		t.Fatal("plaintext should not contain padding characters")
	}
	for _, c := range plaintext {
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			t.Fatalf("plaintext contains non-base32 char %q", c)
		}
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	a := HashToken("HELLO-LMDM")
	b := HashToken("HELLO-LMDM")
	if string(a) != string(b) {
		t.Fatal("HashToken must be deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("hash size = %d, want 32 (SHA-256)", len(a))
	}
}

func TestHashTokenChangesWithInput(t *testing.T) {
	a := HashToken("HELLO-LMDM")
	b := HashToken("HELLO-lmdm")
	if string(a) == string(b) {
		t.Fatal("HashToken must be case-sensitive (no normalization)")
	}
}
