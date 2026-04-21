// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mockNftRunner records calls and returns canned responses.
type mockNftRunner struct {
	calls  [][]string // each invocation's args
	output []byte
	err    error
	// perCall allows different responses per call index.
	perCall []mockNftCall
}

type mockNftCall struct {
	output []byte
	err    error
}

func (m *mockNftRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	callIdx := len(m.calls)
	m.calls = append(m.calls, args)
	if callIdx < len(m.perCall) {
		return m.perCall[callIdx].output, m.perCall[callIdx].err
	}
	return m.output, m.err
}

func (m *mockNftRunner) RunStdin(_ context.Context, _ []byte, args ...string) ([]byte, error) {
	callIdx := len(m.calls)
	m.calls = append(m.calls, args)
	if callIdx < len(m.perCall) {
		return m.perCall[callIdx].output, m.perCall[callIdx].err
	}
	return m.output, m.err
}

// errNftRunner always returns ENOENT (nft not found).
type errNftRunner struct{ err error }

func (e errNftRunner) Run(_ context.Context, _ ...string) ([]byte, error) {
	return nil, e.err
}
func (e errNftRunner) RunStdin(_ context.Context, _ []byte, _ ...string) ([]byte, error) {
	return nil, e.err
}

// withNftRunner temporarily replaces the package-level nft runner for a test.
func withNftRunner(t *testing.T, r nftRunner) {
	t.Helper()
	orig := defaultNftRunner
	defaultNftRunner = r
	t.Cleanup(func() { defaultNftRunner = orig })
}

func withNftablesDir(t *testing.T, dir string) {
	t.Helper()
	orig := nftablesDir
	nftablesDir = dir
	t.Cleanup(func() { nftablesDir = orig })
}

func withNftablesMainConf(t *testing.T, path string) {
	t.Helper()
	orig := nftablesMainConf
	nftablesMainConf = path
	t.Cleanup(func() { nftablesMainConf = orig })
}

// TestNftablesRules_ApplyHappyPath verifies that Apply:
//   - writes the .nft file
//   - calls nft -c -f <path> (dry-run)
//   - calls nft -f /etc/nftables.conf (reload)
func TestNftablesRules_ApplyHappyPath(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	runner := &mockNftRunner{}
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "test",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	ctx := context.Background()
	if err := a.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// File must exist on disk.
	nftFile := filepath.Join(dir, "lmdm-test.nft")
	data, err := os.ReadFile(nftFile) //nolint:gosec
	if err != nil {
		t.Fatalf("nft file missing after Apply: %v", err)
	}
	if string(data) != "table inet filter {}" {
		t.Errorf("unexpected file content: %q", string(data))
	}

	// Expect exactly 2 runner calls.
	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 nft calls, got %d: %v", len(runner.calls), runner.calls)
	}
	// First call: nft -c -f <path>
	if len(runner.calls[0]) < 3 || runner.calls[0][0] != "-c" || runner.calls[0][1] != "-f" {
		t.Errorf("first call should be [-c -f <path>], got %v", runner.calls[0])
	}
	// Second call: nft -f /etc/nftables.conf
	if len(runner.calls[1]) < 2 || runner.calls[1][0] != "-f" || runner.calls[1][1] != "/etc/nftables.conf" {
		t.Errorf("second call should be [-f /etc/nftables.conf], got %v", runner.calls[1])
	}
}

// TestNftablesRules_ApplyDryRunFailure_DeletesFile verifies that when the
// dry-run nft -c -f fails, Apply returns an error AND the .nft file is NOT
// left on disk.
func TestNftablesRules_ApplyDryRunFailure_DeletesFile(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	runner := &mockNftRunner{
		perCall: []mockNftCall{
			{output: []byte("syntax error"), err: errors.New("exit status 1")},
		},
	}
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "badrules",
		"content": "this is invalid nft content!!!",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	ctx := context.Background()
	applyErr := a.Apply(ctx)
	if applyErr == nil {
		t.Fatal("Apply must return error when dry-run fails")
	}
	if !strings.Contains(applyErr.Error(), "syntax error") && !strings.Contains(applyErr.Error(), "dry-run") {
		t.Logf("Apply error: %v", applyErr)
	}

	// The .nft file must NOT exist after rollback.
	nftFile := filepath.Join(dir, "lmdm-badrules.nft")
	if _, err := os.Stat(nftFile); !os.IsNotExist(err) {
		t.Errorf("expected .nft file to be deleted after dry-run failure, stat err: %v", err)
	}
}

// TestNftablesRules_VerifyDriftsOnContentChange verifies that after Apply,
// mutating the file causes Verify to return (false, <reason>, nil).
func TestNftablesRules_VerifyDriftsOnContentChange(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	runner := &mockNftRunner{} // all calls succeed (zero value returns nil err)
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "drift",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	ctx := context.Background()
	if err := a.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Tamper with the file.
	nftFile := filepath.Join(dir, "lmdm-drift.nft")
	if err := os.WriteFile(nftFile, []byte("table inet filter { chain input {} }"), 0o644); err != nil { //nolint:gosec
		t.Fatalf("WriteFile: %v", err)
	}

	// Reset runner call count for Verify.
	runner.calls = nil

	ok, reason, err := a.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("Verify must return false on content drift")
	}
	if reason == "" {
		t.Error("Verify must return a non-empty reason on drift")
	}
}

// TestNftablesRules_SnapshotCapturesRuleset verifies that Snapshot:
//   - calls nft list ruleset
//   - writes the output to {snapDir}/nftables-{name}.ruleset
//   - backs up the existing .nft file if present
func TestNftablesRules_SnapshotCapturesRuleset(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	rulesetOutput := []byte("table inet filter { }\n")
	runner := &mockNftRunner{
		perCall: []mockNftCall{
			{output: rulesetOutput, err: nil}, // list ruleset
		},
	}
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "snap",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	// Pre-create the .nft file to test file backup.
	nftFile := filepath.Join(dir, "lmdm-snap.nft")
	if err := os.WriteFile(nftFile, []byte("table inet filter {}"), 0o644); err != nil { //nolint:gosec
		t.Fatalf("WriteFile: %v", err)
	}

	snapDir := t.TempDir()
	ctx := context.Background()
	if err := a.Snapshot(ctx, snapDir); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Check ruleset file was written.
	rulesetFile := filepath.Join(snapDir, "nftables-snap.ruleset")
	data, err := os.ReadFile(rulesetFile) //nolint:gosec
	if err != nil {
		t.Fatalf("ruleset snapshot missing: %v", err)
	}
	if string(data) != string(rulesetOutput) {
		t.Errorf("ruleset content mismatch: got %q, want %q", string(data), string(rulesetOutput))
	}

	// Check that "list" and "ruleset" appeared in the runner call.
	if len(runner.calls) == 0 {
		t.Fatal("expected at least one nft call for list ruleset")
	}
	found := false
	for _, call := range runner.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "list") && strings.Contains(joined, "ruleset") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'list ruleset' call, got: %v", runner.calls)
	}

	// Check that the .nft file was backed up.
	backupPath := filepath.Join(snapDir, "files", "etc", "nftables.d", "lmdm-snap.nft")
	if _, err := os.Stat(backupPath); err != nil {
		t.Errorf("expected .nft backup at %s: %v", backupPath, err)
	}
}

// TestNftablesRules_SnapshotNoNft verifies that when nft is unavailable
// (ENOENT), Snapshot returns nil and logs a warning (no panic).
func TestNftablesRules_SnapshotNoNft(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	runner := errNftRunner{err: os.ErrNotExist}
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "nonft",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	snapDir := t.TempDir()
	ctx := context.Background()
	if err := a.Snapshot(ctx, snapDir); err != nil {
		t.Fatalf("Snapshot with unavailable nft must return nil, got: %v", err)
	}
}

// TestNftablesRules_RollbackRemovesFileAndReappliesRuleset verifies that
// Rollback deletes the managed .nft file and re-applies the snapshotted ruleset.
func TestNftablesRules_RollbackRemovesFileAndReappliesRuleset(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	runner := &mockNftRunner{}
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "rb",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	// Create the managed .nft file (simulating post-Apply state).
	nftFile := filepath.Join(dir, "lmdm-rb.nft")
	if err := os.WriteFile(nftFile, []byte("table inet filter {}"), 0o644); err != nil { //nolint:gosec
		t.Fatalf("WriteFile: %v", err)
	}

	// Create a snapshot directory with a ruleset file.
	snapDir := t.TempDir()
	rulesetContent := []byte("table inet filter { }\n")
	rulesetFile := filepath.Join(snapDir, "nftables-rb.ruleset")
	if err := os.WriteFile(rulesetFile, rulesetContent, 0o600); err != nil { //nolint:gosec
		t.Fatalf("WriteFile ruleset: %v", err)
	}

	ctx := context.Background()
	rb, ok := a.(RollbackProvider)
	if !ok {
		t.Fatal("NftablesRules must implement RollbackProvider")
	}

	if err := rb.Rollback(ctx, snapDir); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// Managed file must be gone.
	if _, err := os.Stat(nftFile); !os.IsNotExist(err) {
		t.Errorf("managed .nft file must be deleted by Rollback, stat: %v", err)
	}

	// Runner must have been called with nft -f <rulesetFile>.
	if len(runner.calls) == 0 {
		t.Fatal("expected nft call for ruleset re-apply")
	}
	found := false
	for _, call := range runner.calls {
		if len(call) >= 2 && call[0] == "-f" && call[1] == rulesetFile {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected '-f %s' call, got: %v", rulesetFile, runner.calls)
	}
}

// TestNftablesRules_RejectsUnsafeName verifies that the constructor rejects
// names containing path traversal or unsafe characters.
func TestNftablesRules_RejectsUnsafeName(t *testing.T) {
	unsafe := []string{
		"../etc",
		"bad/name",
		"name with space",
		"toolongnamethatexceeds64characterslimittoolongnamethatexceeds64ch",
		"",
	}
	for _, name := range unsafe {
		_, err := NewNftablesRules(map[string]any{
			"name":    name,
			"content": "table inet filter {}",
		})
		if err == nil {
			t.Errorf("expected error for unsafe name %q", name)
		}
	}
}

// TestNftablesRules_RejectsEmptyContent verifies that empty content is rejected.
func TestNftablesRules_RejectsEmptyContent(t *testing.T) {
	_, err := NewNftablesRules(map[string]any{
		"name":    "valid",
		"content": "",
	})
	if err == nil {
		t.Error("expected error for empty content")
	}
}

// TestNftablesRules_SnapshotFailsOnNonENOENTError verifies that Snapshot returns
// a non-nil error when nft list ruleset fails for a reason other than binary-not-found.
// Previously the error was silently swallowed, leaving rollback without a ruleset.
func TestNftablesRules_SnapshotFailsOnNonENOENTError(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	runner := errNftRunner{err: errors.New("nft: permission denied")}
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "permerr",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	snapDir := t.TempDir()
	ctx := context.Background()
	snapErr := a.Snapshot(ctx, snapDir)
	if snapErr == nil {
		t.Fatal("Snapshot must return a non-nil error when nft list ruleset fails with a non-ENOENT error")
	}
}

// TestNftablesRules_PostRollbackReloadsConfig verifies that PostRollback calls
// nft -f <nftablesMainConf> when the config file exists.
func TestNftablesRules_PostRollbackReloadsConfig(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	// Create a fake main conf file so the stat check passes.
	fakeConf := filepath.Join(t.TempDir(), "nftables.conf")
	if err := os.WriteFile(fakeConf, []byte("flush ruleset\n"), 0o644); err != nil { //nolint:gosec
		t.Fatalf("WriteFile: %v", err)
	}
	withNftablesMainConf(t, fakeConf)

	runner := &mockNftRunner{}
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "post-rb",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	prb, ok := a.(PostRollbackProvider)
	if !ok {
		t.Fatal("NftablesRules must implement PostRollbackProvider")
	}

	ctx := context.Background()
	if err := prb.PostRollback(ctx, t.TempDir()); err != nil {
		t.Fatalf("PostRollback: %v", err)
	}

	// Must have called nft -f <fakeConf>.
	if len(runner.calls) == 0 {
		t.Fatal("expected nft call in PostRollback")
	}
	found := false
	for _, call := range runner.calls {
		if len(call) >= 2 && call[0] == "-f" && call[1] == fakeConf {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected '-f %s' call, got: %v", fakeConf, runner.calls)
	}
}

// TestNftablesRules_PostRollbackSkipsWhenNftMissing verifies that PostRollback
// returns nil when the nft binary is not found (exec.ErrNotFound).
func TestNftablesRules_PostRollbackSkipsWhenNftMissing(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	fakeConf := filepath.Join(t.TempDir(), "nftables.conf")
	if err := os.WriteFile(fakeConf, []byte("flush ruleset\n"), 0o644); err != nil { //nolint:gosec
		t.Fatalf("WriteFile: %v", err)
	}
	withNftablesMainConf(t, fakeConf)

	// Simulate exec.ErrNotFound using the same exec.Error wrapper that
	// exec.Command returns when the binary is not in PATH.
	notFoundErr := &exec.Error{Name: "nft", Err: exec.ErrNotFound}
	withNftRunner(t, errNftRunner{err: notFoundErr})

	a, err := NewNftablesRules(map[string]any{
		"name":    "nomissing",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	prb, ok := a.(PostRollbackProvider)
	if !ok {
		t.Fatal("NftablesRules must implement PostRollbackProvider")
	}

	ctx := context.Background()
	if err := prb.PostRollback(ctx, t.TempDir()); err != nil {
		t.Fatalf("PostRollback must return nil when nft is missing, got: %v", err)
	}
}

// TestNftablesRules_PostRollbackSkipsWhenConfMissing verifies that PostRollback
// returns nil without calling the runner when nftablesMainConf does not exist.
func TestNftablesRules_PostRollbackSkipsWhenConfMissing(t *testing.T) {
	dir := t.TempDir()
	withNftablesDir(t, dir)

	// Point to a path that does not exist.
	withNftablesMainConf(t, filepath.Join(t.TempDir(), "nonexistent.conf"))

	runner := &mockNftRunner{}
	withNftRunner(t, runner)

	a, err := NewNftablesRules(map[string]any{
		"name":    "noconf",
		"content": "table inet filter {}",
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	prb, ok := a.(PostRollbackProvider)
	if !ok {
		t.Fatal("NftablesRules must implement PostRollbackProvider")
	}

	ctx := context.Background()
	if err := prb.PostRollback(ctx, t.TempDir()); err != nil {
		t.Fatalf("PostRollback must return nil when conf is missing, got: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("runner must not be called when conf is missing, got calls: %v", runner.calls)
	}
}
