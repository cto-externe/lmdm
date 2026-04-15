// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectTPMAbsentReturnsNil(t *testing.T) {
	dir := t.TempDir() // empty: no tpm0 subdir
	tpm := collectTPMFrom(dir)
	if tpm != nil {
		t.Errorf("TPM should be nil when /sys/class/tpm/tpm0 is absent, got %+v", tpm)
	}
}

func TestCollectTPMPresent(t *testing.T) {
	dir := t.TempDir()
	tpmDir := filepath.Join(dir, "tpm0")
	if err := os.MkdirAll(tpmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tpmDir, "tpm_version_major"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tpmDir, "tpm_version_minor"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tpm := collectTPMFrom(dir)
	if tpm == nil {
		t.Fatal("TPM should be non-nil when tpm0 exists")
	}
	if !tpm.Present {
		t.Error("Present should be true on a real TPM")
	}
	if tpm.Version != "2.0" {
		t.Errorf("Version = %q, want 2.0", tpm.Version)
	}
}
