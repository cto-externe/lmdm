// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateSnapshotDir(t *testing.T) {
	root := t.TempDir()
	dir, err := CreateSnapshotDir(root, "deploy-001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("snapshot dir not created: %v", err)
	}
	expected := filepath.Join(root, "deploy-001")
	if dir != expected {
		t.Errorf("dir = %q, want %q", dir, expected)
	}
}
