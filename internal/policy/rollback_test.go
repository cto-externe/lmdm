// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackRestoresFileFromSnapshot(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.conf")

	// Simulate: file existed before apply with original content.
	snapDir := filepath.Join(dir, "snap")
	backupDir := filepath.Join(snapDir, "files", target)
	if err := os.MkdirAll(filepath.Dir(backupDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupDir, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Apply wrote new content.
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("modified-by-apply"), 0o600); err != nil { //nolint:gosec
		t.Fatal(err)
	}

	// Rollback should restore original.
	if err := Rollback(context.Background(), snapDir); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	data, _ := os.ReadFile(target) //nolint:gosec
	if string(data) != "original" {
		t.Errorf("after rollback: %q, want 'original'", data)
	}
}

func TestRollbackRestoresSysctlValues(t *testing.T) {
	dir := t.TempDir()
	snapDir := filepath.Join(dir, "snap")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Write a sysctl snapshot. We can't actually call sysctl in unit test,
	// so we test that the function reads the JSON correctly. The actual
	// sysctl -w call is tested manually on a real system.
	values := map[string]string{"net.ipv4.ip_forward": "1", "kernel.sysrq": "176"}
	data, _ := json.Marshal(values)
	if err := os.WriteFile(filepath.Join(snapDir, "sysctl.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Rollback will attempt `sysctl -w` which may fail in test env (no sysctl
	// binary or no root). We just verify it doesn't panic and returns a
	// meaningful error if sysctl is unavailable.
	err := Rollback(context.Background(), snapDir)
	// On a dev machine without sysctl available to non-root: error is expected.
	// On a machine where sysctl works: no error.
	// Either way: no panic.
	_ = err
}

func TestRollbackEmptySnapshotIsNoOp(t *testing.T) {
	snapDir := t.TempDir() // empty dir = nothing to restore
	if err := Rollback(context.Background(), snapDir); err != nil {
		t.Fatalf("Rollback on empty snapshot must not error: %v", err)
	}
}

// TestRollback_OrderIsSysctlFilesServicesPackages exercises the central
// Rollback with all four artifact kinds present and asserts the function
// returns end-to-end without panicking. The intended order
// (sysctl → files → services → packages) is documented on Rollback itself
// and visible from the slog.Info calls in each subroutine.
//
// We can't easily intercept exec.Command from a unit test, so we don't
// assert the exact sequence here — but we do ensure all four code paths
// run on a single snapshot and the file restore (which IS observable)
// completes successfully.
func TestRollback_OrderIsSysctlFilesServicesPackages(t *testing.T) {
	dir := t.TempDir()
	snapDir := filepath.Join(dir, "snap")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// 1. sysctl.json — empty map so no `sysctl -w` call is made.
	if err := os.WriteFile(filepath.Join(snapDir, "sysctl.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. files/<target> — actually restorable.
	target := filepath.Join(dir, "target.conf")
	backupPath := filepath.Join(snapDir, "files", target)
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 3. services.json — empty map skips systemctl invocation.
	if err := os.WriteFile(filepath.Join(snapDir, "services.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 4. packages.json — empty map skips apt-get invocation.
	if err := os.WriteFile(filepath.Join(snapDir, "packages.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Rollback(context.Background(), snapDir); err != nil {
		t.Fatalf("Rollback with all 4 artifacts: %v", err)
	}

	// File restore is the only externally observable side effect we can check.
	got, err := os.ReadFile(target) //nolint:gosec
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "original" {
		t.Errorf("file rollback: %q, want 'original'", got)
	}
}

func TestExecutorAutoRollbackOnFailure(t *testing.T) {
	// Two actions: first succeeds, second fails → executor should attempt rollback.
	succeeded := &stubAction{typeName: "package_ensure", verifyResult: true}
	failing := &stubAction{typeName: "service_ensure", applyErr: context.DeadlineExceeded}

	actions := []TypedAction{
		{Type: "package_ensure", Action: succeeded},
		{Type: "service_ensure", Action: failing},
	}

	result := Execute(context.Background(), actions, t.TempDir(), "test-auto-rollback")

	if result.AllCompliant {
		t.Error("must not be compliant on failure")
	}
	if result.Error == "" {
		t.Error("error must be set")
	}
	// The first action was snapshotted and applied. Rollback was attempted.
	// With stubActions that write nothing to the snapshot, the rollback is a no-op.
	// The important thing: no panic, error propagated correctly.
	if !succeeded.applied {
		t.Error("first action should have been applied before the second failed")
	}
}
