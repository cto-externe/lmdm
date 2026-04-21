// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestKernelModuleBlacklist_ApplyWritesFile(t *testing.T) {
	dir := t.TempDir()
	orig := modprobeDir
	modprobeDir = dir
	t.Cleanup(func() { modprobeDir = orig })

	a, err := NewKernelModuleBlacklist(map[string]any{
		"name":    "test",
		"modules": []any{"cramfs", "usb_storage"},
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	ctx := context.Background()
	if err := a.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "lmdm-test.conf")) //nolint:gosec
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !containsLine(content, "install cramfs /bin/true") {
		t.Errorf("expected 'install cramfs /bin/true' in:\n%s", content)
	}
	if !containsLine(content, "install usb_storage /bin/true") {
		t.Errorf("expected 'install usb_storage /bin/true' in:\n%s", content)
	}
}

func TestKernelModuleBlacklist_VerifyDetectsDrift(t *testing.T) {
	dir := t.TempDir()
	orig := modprobeDir
	modprobeDir = dir
	t.Cleanup(func() { modprobeDir = orig })

	a, err := NewKernelModuleBlacklist(map[string]any{
		"name":    "drift",
		"modules": []any{"cramfs"},
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	ctx := context.Background()
	if err := a.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Mutate the on-disk file.
	confPath := filepath.Join(dir, "lmdm-drift.conf")
	if err := os.WriteFile(confPath, []byte("tampered content\n"), 0o644); err != nil { //nolint:gosec
		t.Fatalf("WriteFile: %v", err)
	}

	ok, reason, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("Verify must return false on drift")
	}
	if reason != "file content drift" {
		t.Errorf("reason = %q, want %q", reason, "file content drift")
	}
}

func TestKernelModuleBlacklist_VerifyFileMissing(t *testing.T) {
	dir := t.TempDir()
	orig := modprobeDir
	modprobeDir = dir
	t.Cleanup(func() { modprobeDir = orig })

	a, err := NewKernelModuleBlacklist(map[string]any{
		"name":    "missing",
		"modules": []any{"cramfs"},
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	ctx := context.Background()
	// No Apply — file does not exist.
	ok, reason, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("Verify must return false when file is missing")
	}
	if reason != "file missing" {
		t.Errorf("reason = %q, want %q", reason, "file missing")
	}
}

func TestKernelModuleBlacklist_SnapshotRollback_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := modprobeDir
	modprobeDir = dir
	t.Cleanup(func() { modprobeDir = orig })

	a, err := NewKernelModuleBlacklist(map[string]any{
		"name":    "snap",
		"modules": []any{"cramfs"},
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	ctx := context.Background()
	snapDir := filepath.Join(dir, "snap")
	if err := os.MkdirAll(snapDir, 0o750); err != nil {
		t.Fatalf("MkdirAll snapDir: %v", err)
	}

	// Snapshot before Apply: file is absent — no artifact must be written under
	// snapDir/files/ (writing a .absent sentinel would be restored verbatim by the
	// central rollback walker, creating a garbage file on the live system).
	if err := a.Snapshot(ctx, snapDir); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	filesDir := filepath.Join(snapDir, "files")
	var artifactCount int
	_ = filepath.Walk(filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // missing root is fine
		}
		if !info.IsDir() {
			artifactCount++
		}
		return nil
	})
	if artifactCount != 0 {
		t.Errorf("expected no artifacts under %s when source file absent, got %d", filesDir, artifactCount)
	}

	// Snapshot after Apply: the conf file must be backed up.
	if err := a.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	snapDir2 := filepath.Join(dir, "snap2")
	if err := os.MkdirAll(snapDir2, 0o750); err != nil {
		t.Fatalf("MkdirAll snapDir2: %v", err)
	}
	if err := a.Snapshot(ctx, snapDir2); err != nil {
		t.Fatalf("Snapshot after Apply: %v", err)
	}
	backupPath := filepath.Join(snapDir2, "files", "etc", "modprobe.d", "lmdm-snap.conf")
	if _, err := os.Stat(backupPath); err != nil {
		t.Errorf("expected backup at %s after Apply: %v", backupPath, err)
	}
}

func TestKernelModuleBlacklist_RejectsUnsafeName(t *testing.T) {
	cases := []string{"../../etc", "bad/name", "name with space", "toolongnamethatexceeds64characterslimittoolongnamethatexceeds64ch"}
	for _, name := range cases {
		_, err := NewKernelModuleBlacklist(map[string]any{
			"name":    name,
			"modules": []any{"cramfs"},
		})
		if err == nil {
			t.Errorf("expected error for name %q", name)
		}
	}
}

func TestKernelModuleBlacklist_RejectsUnsafeModuleName(t *testing.T) {
	// Module names must not contain dashes.
	_, err := NewKernelModuleBlacklist(map[string]any{
		"name":    "test",
		"modules": []any{"usb-storage"},
	})
	if err == nil {
		t.Error("expected error for module name with dash 'usb-storage'")
	}
}

// containsLine returns true if s contains the given line (possibly surrounded by newlines).
func containsLine(s, line string) bool {
	for _, l := range splitLines(s) {
		if l == line {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
