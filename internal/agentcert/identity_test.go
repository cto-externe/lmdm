package agentcert

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.identity")

	id := &Identity{
		SignedCert: []byte("fake-signed-cert-bytes"),
		ServerPub: &pqhybrid.SigningPublicKey{
			Ed25519: []byte("server-ed25519-pub"),
			MLDSA:   []byte("server-mldsa-pub"),
		},
	}
	if err := Save(path, id); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got.SignedCert) != string(id.SignedCert) {
		t.Errorf("SignedCert mismatch")
	}
	if string(got.ServerPub.Ed25519) != string(id.ServerPub.Ed25519) {
		t.Errorf("ServerPub.Ed25519 mismatch")
	}
	if string(got.ServerPub.MLDSA) != string(id.ServerPub.MLDSA) {
		t.Errorf("ServerPub.MLDSA mismatch")
	}
}

func TestLoadRejectsCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.identity")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load must reject corrupted file")
	}
}

func TestLoadReturnsErrNotExistWhenMissing(t *testing.T) {
	_, err := Load("/nonexistent/path/agent.identity")
	if err == nil {
		t.Fatal("Load must error on missing file")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("Load error must wrap fs.ErrNotExist, got %v", err)
	}
}
