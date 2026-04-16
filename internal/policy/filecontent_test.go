// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNewFileContentValid(t *testing.T) {
	params := map[string]any{
		"path":    "/etc/chrony/chrony.conf",
		"content": "server 0.fr.pool.ntp.org iburst\n",
	}
	a, err := NewFileContent(params)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNewFileContentMissingPath(t *testing.T) {
	_, err := NewFileContent(map[string]any{"content": "x"})
	if err == nil {
		t.Fatal("must reject missing path")
	}
}

func TestFileContentApplyAndVerify(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test.conf")

	a, _ := NewFileContent(map[string]any{
		"path":    target,
		"content": "hello world\n",
	})
	ctx := context.Background()

	// Snapshot (file doesn't exist yet — should not error).
	snapDir := filepath.Join(dir, "snap")
	_ = os.MkdirAll(snapDir, 0o750) //nolint:gosec
	if err := a.Snapshot(ctx, snapDir); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Apply.
	if err := a.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	data, _ := os.ReadFile(target) //nolint:gosec
	if string(data) != "hello world\n" {
		t.Errorf("file content = %q", data)
	}

	// Verify.
	ok, reason, err := a.Verify(ctx)
	if err != nil || !ok {
		t.Errorf("Verify: ok=%v reason=%q err=%v", ok, reason, err)
	}

	// Tamper → Verify detects drift.
	_ = os.WriteFile(target, []byte("tampered"), 0o600) //nolint:gosec
	ok, reason, _ = a.Verify(ctx)
	if ok {
		t.Error("Verify must detect tampered file")
	}
	if reason == "" {
		t.Error("reason should describe the drift")
	}
}
