// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

// Hermetic integration tests for ANSSI profile actions.
//
// These tests parse real profile YAML files and apply only the action types
// whose filesystem writes can be redirected to a t.TempDir() sandbox:
//   - kernel_module_blacklist  → modprobeDir override
//   - nftables_rules           → nftablesDir + defaultNftRunner override
//
// Actions that invoke real system binaries (sysctl, apt, systemctl) or write
// to absolute paths without a redirect hook (file_content) are filtered out
// so the test remains hermetic and container-safe.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hermeticTypes is the set of action types this test can run without
// shelling out to real system binaries.
var hermeticTypes = map[string]bool{
	"kernel_module_blacklist": true,
	"nftables_rules":          true,
}

// parseProfileForE2E parses a profile YAML and returns only the hermetic actions.
func parseProfileForE2E(t *testing.T, path string) []TypedAction {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		t.Fatalf("read profile %s: %v", path, err)
	}
	_, all, err := ParseProfile(data, DefaultRegistry())
	if err != nil {
		t.Fatalf("parse profile %s: %v", path, err)
	}
	var filtered []TypedAction
	for _, ta := range all {
		if hermeticTypes[ta.Type] {
			filtered = append(filtered, ta)
		}
	}
	return filtered
}

// TestIntegrationANSSIRenforceHermetic applies the kernel_module_blacklist and
// nftables_rules actions from anssi-renforce.yml against a tempdir sandbox.
//
// It verifies:
//   - modprobe drop-in files are written with the expected content
//   - nftables fragment files are written with the expected content
//   - the mock nft runner receives a dry-run (-c -f) call for each nftables action
func TestIntegrationANSSIRenforceHermetic(t *testing.T) {
	sandbox := t.TempDir()
	modDir := filepath.Join(sandbox, "modprobe.d")
	nftDir := filepath.Join(sandbox, "nftables.d")
	snapDir := filepath.Join(sandbox, "snap")

	// Redirect filesystem-writing package vars to the sandbox.
	origModprobe := modprobeDir
	modprobeDir = modDir
	t.Cleanup(func() { modprobeDir = origModprobe })

	origNftables := nftablesDir
	nftablesDir = nftDir
	t.Cleanup(func() { nftablesDir = origNftables })

	// Replace the nft runner with a mock that always succeeds.
	mock := &mockNftRunner{}
	origRunner := defaultNftRunner
	defaultNftRunner = mock
	t.Cleanup(func() { defaultNftRunner = origRunner })

	if err := os.MkdirAll(snapDir, 0o750); err != nil {
		t.Fatalf("MkdirAll snapDir: %v", err)
	}

	profile := filepath.Join("..", "..", "profiles", "anssi", "anssi-renforce.yml")
	actions := parseProfileForE2E(t, profile)

	if len(actions) == 0 {
		t.Fatal("no hermetic actions found in anssi-renforce.yml — profile may have changed")
	}

	var nftActions, modActions int
	for _, ta := range actions {
		switch ta.Type {
		case "kernel_module_blacklist":
			modActions++
		case "nftables_rules":
			nftActions++
		}
	}
	t.Logf("hermetic actions: %d kernel_module_blacklist, %d nftables_rules", modActions, nftActions)

	if modActions == 0 {
		t.Error("expected at least one kernel_module_blacklist action in anssi-renforce.yml")
	}
	if nftActions == 0 {
		t.Error("expected at least one nftables_rules action in anssi-renforce.yml")
	}

	ctx := context.Background()

	// Apply every hermetic action: Snapshot then Apply.
	for _, ta := range actions {
		if err := ta.Action.Snapshot(ctx, snapDir); err != nil {
			t.Errorf("[%s] Snapshot failed: %v", ta.Type, err)
			continue
		}
		if err := ta.Action.Apply(ctx); err != nil {
			t.Errorf("[%s] Apply failed: %v", ta.Type, err)
		}
	}

	// --- Assertions: kernel_module_blacklist ---
	//
	// For each .conf file under modDir, verify it contains at least one
	// "install <module> /bin/true" line.
	entries, err := os.ReadDir(modDir)
	if err != nil {
		t.Fatalf("ReadDir modDir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected modprobe drop-in files to be written under the sandbox")
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(modDir, e.Name())) //nolint:gosec
		if err != nil {
			t.Errorf("ReadFile %s: %v", e.Name(), err)
			continue
		}
		content := string(data)
		if !strings.Contains(content, "install ") || !strings.Contains(content, "/bin/true") {
			t.Errorf("%s: expected 'install <module> /bin/true' lines, got:\n%s", e.Name(), content)
		}
	}

	// --- Assertions: nftables_rules ---
	//
	// For each .nft file under nftDir, verify it is non-empty.
	nftEntries, err := os.ReadDir(nftDir)
	if err != nil {
		t.Fatalf("ReadDir nftDir: %v", err)
	}
	if len(nftEntries) == 0 {
		t.Error("expected nftables fragment files to be written under the sandbox")
	}
	for _, e := range nftEntries {
		if !strings.HasSuffix(e.Name(), ".nft") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(nftDir, e.Name())) //nolint:gosec
		if err != nil {
			t.Errorf("ReadFile %s: %v", e.Name(), err)
			continue
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			t.Errorf("%s: nftables fragment file is empty", e.Name())
		}
	}

	// --- Assertions: mock nft runner received dry-run call(s) ---
	//
	// Apply calls: nft -c -f <path>  (dry-run) then nft -f /etc/nftables.conf (reload).
	// We verify at least one dry-run (-c -f) call was made.
	dryRunSeen := false
	for _, call := range mock.calls {
		if len(call) >= 2 && call[0] == "-c" && call[1] == "-f" {
			dryRunSeen = true
			break
		}
	}
	if !dryRunSeen {
		t.Errorf("expected at least one 'nft -c -f <path>' dry-run call; got calls: %v", mock.calls)
	}
}

// TestIntegrationANSSIIntermediaireHermetic applies the nftables_rules action
// from anssi-intermediaire.yml against a tempdir sandbox.
//
// anssi-intermediaire does not contain kernel_module_blacklist (that starts at
// renforcé), so this test exercises nftables_rules only.
func TestIntegrationANSSIIntermediaireHermetic(t *testing.T) {
	sandbox := t.TempDir()
	nftDir := filepath.Join(sandbox, "nftables.d")
	snapDir := filepath.Join(sandbox, "snap")

	origNftables := nftablesDir
	nftablesDir = nftDir
	t.Cleanup(func() { nftablesDir = origNftables })

	mock := &mockNftRunner{}
	origRunner := defaultNftRunner
	defaultNftRunner = mock
	t.Cleanup(func() { defaultNftRunner = origRunner })

	if err := os.MkdirAll(snapDir, 0o750); err != nil {
		t.Fatalf("MkdirAll snapDir: %v", err)
	}

	profile := filepath.Join("..", "..", "profiles", "anssi", "anssi-intermediaire.yml")
	actions := parseProfileForE2E(t, profile)

	var nftCount int
	for _, ta := range actions {
		if ta.Type == "nftables_rules" {
			nftCount++
		}
	}
	t.Logf("hermetic nftables_rules actions in anssi-intermediaire.yml: %d", nftCount)

	if nftCount == 0 {
		t.Fatal("expected at least one nftables_rules action in anssi-intermediaire.yml")
	}

	ctx := context.Background()
	for _, ta := range actions {
		if err := ta.Action.Snapshot(ctx, snapDir); err != nil {
			t.Errorf("[%s] Snapshot failed: %v", ta.Type, err)
			continue
		}
		if err := ta.Action.Apply(ctx); err != nil {
			t.Errorf("[%s] Apply failed: %v", ta.Type, err)
		}
	}

	// Verify nftables fragment files were written.
	nftEntries, err := os.ReadDir(nftDir)
	if err != nil {
		t.Fatalf("ReadDir nftDir: %v", err)
	}
	if len(nftEntries) == 0 {
		t.Error("expected nftables fragment files under sandbox")
	}
	for _, e := range nftEntries {
		if !strings.HasSuffix(e.Name(), ".nft") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(nftDir, e.Name())) //nolint:gosec
		if err != nil {
			t.Errorf("ReadFile %s: %v", e.Name(), err)
			continue
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			t.Errorf("%s: nftables fragment is empty", e.Name())
		}
	}

	// At least one dry-run call expected.
	dryRunSeen := false
	for _, call := range mock.calls {
		if len(call) >= 2 && call[0] == "-c" && call[1] == "-f" {
			dryRunSeen = true
			break
		}
	}
	if !dryRunSeen {
		t.Errorf("expected at least one 'nft -c -f' call; got: %v", mock.calls)
	}
}
