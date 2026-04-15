package serverkey

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateCreatesNewKeyOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.key")

	priv, pub, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if priv == nil || pub == nil {
		t.Fatal("returned nil keys")
	}

	// File must exist on disk now.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not persisted: %v", err)
	}

	// Permissions must be restrictive (owner read/write only).
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestLoadOrGenerateReturnsSameKeyOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.key")

	priv1, pub1, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := LoadOrGenerate(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(priv1.Ed25519) != string(priv2.Ed25519) {
		t.Fatal("Ed25519 priv differs across loads")
	}
	if string(pub1.MLDSA) != string(pub2.MLDSA) {
		t.Fatal("ML-DSA pub differs across loads")
	}
}
