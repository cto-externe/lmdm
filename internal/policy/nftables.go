// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

// nftablesDir is the directory where nftables drop-in files are written.
// Overridable in tests.
var nftablesDir = "/etc/nftables.d"

// nftablesMainConf is the main nftables config file loaded by the kernel.
// Overridable in tests to avoid touching the real system path.
var nftablesMainConf = "/etc/nftables.conf"

// nftCmd is the nft binary path, overridable in tests.
var nftCmd = "nft" //nolint:unused // used via defaultNftRunner init

// nftRunner abstracts nft invocations so tests can inject a mock.
type nftRunner interface {
	// Run executes nft with the given args and returns combined output.
	Run(ctx context.Context, args ...string) ([]byte, error)
	// RunStdin executes nft with the given args, feeding stdin to it.
	RunStdin(ctx context.Context, stdin []byte, args ...string) ([]byte, error)
}

// execNftRunner is the production nftRunner backed by os/exec.
type execNftRunner struct{}

func (execNftRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, nftCmd, args...) //nolint:gosec
	return cmd.CombinedOutput()
}

func (execNftRunner) RunStdin(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, nftCmd, args...) //nolint:gosec
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.CombinedOutput()
}

// defaultNftRunner is the package-level runner used by NftablesRules.
// Tests replace this to avoid executing real nft commands.
var defaultNftRunner nftRunner = execNftRunner{}

// NftablesRules writes an nftables drop-in fragment and validates + reloads
// the in-kernel ruleset via nft.
type NftablesRules struct {
	Name    string
	Content string
}

// getRunner returns the current package-level nft runner.
// Reading it on each call (rather than capturing at construction time) avoids
// test-ordering hazards where the package-level var is swapped after the
// struct is built.
func (a *NftablesRules) getRunner() nftRunner {
	return defaultNftRunner
}

// NewNftablesRules constructs a NftablesRules from the YAML params map.
// Validates name (safe [A-Za-z0-9_-]{1,64}) and content (non-empty).
func NewNftablesRules(params map[string]any) (Action, error) {
	name, _ := params["name"].(string)
	if name == "" {
		return nil, errors.New("nftables_rules: name is required")
	}
	if !isSafeName(name) {
		return nil, fmt.Errorf("nftables_rules: unsafe name %q (must match [A-Za-z0-9_-]{1,64})", name)
	}

	content, _ := params["content"].(string)
	if content == "" {
		return nil, errors.New("nftables_rules: content is required and must be non-empty")
	}

	return &NftablesRules{
		Name:    name,
		Content: content,
	}, nil
}

// nftFilePath returns the target path for this action's nftables fragment.
func (a *NftablesRules) nftFilePath() string {
	return filepath.Join(nftablesDir, "lmdm-"+a.Name+".nft")
}

// Validate checks that Name and Content are still well-formed.
func (a *NftablesRules) Validate() error {
	if !isSafeName(a.Name) {
		return fmt.Errorf("nftables_rules: unsafe name %q", a.Name)
	}
	if a.Content == "" {
		return errors.New("nftables_rules: content must be non-empty")
	}
	return nil
}

// Snapshot saves the current state before Apply:
//  1. Runs `nft list ruleset` and writes the output to
//     {snapDir}/nftables-{name}.ruleset (0o600). If nft is unavailable
//     (ENOENT), logs a warning and skips — returns nil.
//  2. If {nftablesDir}/lmdm-{name}.nft already exists, backs it up under
//     {snapDir}/files/etc/nftables.d/lmdm-{name}.nft (FileContent convention).
func (a *NftablesRules) Snapshot(ctx context.Context, snapDir string) error {
	// --- Step 1: capture in-kernel ruleset via nft list ruleset ---
	out, err := a.getRunner().Run(ctx, "list", "ruleset")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || isExecNotFound(err) {
			slog.WarnContext(ctx, "nftables_rules: nft not found, skipping ruleset capture",
				"action_name", a.Name)
		} else {
			// nft found but returned a real error — surface it so the caller
			// knows the snapshot is incomplete and rollback would be degraded.
			return fmt.Errorf("nftables_rules snapshot: nft list ruleset failed: %w", err)
		}
	} else {
		rulesetPath := filepath.Join(snapDir, "nftables-"+a.Name+".ruleset")
		if err := os.WriteFile(rulesetPath, out, 0o600); err != nil { //nolint:gosec
			return fmt.Errorf("nftables_rules snapshot write ruleset: %w", err)
		}
	}

	// --- Step 2: back up existing .nft file if present ---
	src := a.nftFilePath()
	data, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil // file didn't exist before Apply — nothing to back up
		}
		return fmt.Errorf("nftables_rules snapshot read %s: %w", src, err)
	}
	canonicalRel := filepath.Join("etc", "nftables.d", "lmdm-"+a.Name+".nft")
	dest := filepath.Join(snapDir, "files", canonicalRel)
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return fmt.Errorf("nftables_rules snapshot mkdir: %w", err)
	}
	return os.WriteFile(dest, data, 0o600) //nolint:gosec
}

// Apply writes Content to the nftables drop-in file, validates syntax via
// `nft -c -f <path>` (dry-run), and reloads the in-kernel ruleset via
// `nft -f /etc/nftables.conf`.
//
// If the dry-run fails, the written file is deleted (atomic rollback of the
// write) and an error including the nft output is returned.
func (a *NftablesRules) Apply(ctx context.Context) error {
	if err := os.MkdirAll(nftablesDir, 0o755); err != nil { //nolint:gosec
		return fmt.Errorf("nftables_rules mkdir %s: %w", nftablesDir, err)
	}

	target := a.nftFilePath()
	if err := os.WriteFile(target, []byte(a.Content), 0o644); err != nil { //nolint:gosec
		return fmt.Errorf("nftables_rules write %s: %w", target, err)
	}

	// Dry-run syntax check.
	absTarget, err := filepath.Abs(target)
	if err != nil {
		absTarget = target
	}
	out, dryErr := a.getRunner().Run(ctx, "-c", "-f", absTarget)
	if dryErr != nil {
		// Rollback: delete the written file.
		_ = os.Remove(target)
		return fmt.Errorf("nftables_rules dry-run validation failed: %w; nft output: %s", dryErr, string(out))
	}

	// Reload in-kernel ruleset.
	if out, reloadErr := a.getRunner().Run(ctx, "-f", "/etc/nftables.conf"); reloadErr != nil {
		// Leave the file in place for operator inspection;
		// the executor will trigger a rollback via RollbackWithProviders.
		return fmt.Errorf("nftables_rules reload failed: %w; nft output: %s", reloadErr, string(out))
	}

	return nil
}

// Verify checks whether the on-disk fragment matches Content and passes the
// nft dry-run syntax check. It does NOT run `nft list ruleset` (too expensive).
func (a *NftablesRules) Verify(ctx context.Context) (bool, string, error) {
	data, err := os.ReadFile(a.nftFilePath()) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return false, "file missing", nil
		}
		return false, "", fmt.Errorf("nftables_rules verify read: %w", err)
	}

	if string(data) != a.Content {
		return false, "file content drift", nil
	}

	absTarget, err := filepath.Abs(a.nftFilePath())
	if err != nil {
		absTarget = a.nftFilePath()
	}
	if _, syntaxErr := a.getRunner().Run(ctx, "-c", "-f", absTarget); syntaxErr != nil {
		return false, "nftables syntax invalid", nil
	}

	return true, "", nil
}

// Rollback implements RollbackProvider. It:
//  1. Removes the managed /etc/nftables.d/lmdm-{name}.nft file if present.
//  2. Re-applies the snapshotted full ruleset via `nft -f {snapDir}/nftables-{name}.ruleset`.
//     If the ruleset snapshot does not exist (nft was unavailable at snapshot time),
//     only step 1 is performed and a warning is logged.
//
// Note on sequencing: central rollbackFiles runs AFTER Rollback returns and
// will re-write the pre-existing .nft file if it was backed up at snapshot time.
// That on-disk restoration does NOT automatically reload the in-kernel ruleset.
// For the common MVP case (no pre-existing fragment), this Rollback is complete.
// When a pre-existing fragment existed, a manual `nft -f /etc/nftables.conf` or
// `systemctl reload nftables` is needed post-rollback to sync the kernel state.
func (a *NftablesRules) Rollback(ctx context.Context, snapDir string) error {
	// Step 1: remove the managed file.
	target := a.nftFilePath()
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("nftables_rules rollback remove %s: %w", target, err)
	}

	// Step 2: re-apply the snapshotted ruleset (if available).
	rulesetFile := filepath.Join(snapDir, "nftables-"+a.Name+".ruleset")
	if _, err := os.Stat(rulesetFile); os.IsNotExist(err) {
		slog.WarnContext(ctx, "nftables_rules rollback: no ruleset snapshot, skipping re-apply",
			"action_name", a.Name)
		return nil
	}

	out, err := a.getRunner().Run(ctx, "-f", rulesetFile)
	if err != nil {
		return fmt.Errorf("nftables_rules rollback re-apply ruleset failed: %w; nft output: %s", err, string(out))
	}

	return nil
}

// PostRollback implements PostRollbackProvider. It re-reads nftablesMainConf
// into the kernel to bring the in-memory ruleset in sync with any fragment
// file that the central rollbackFiles phase restored.
//
// Best-effort: if nft is not installed or the main config file does not exist,
// logs and returns nil (non-fatal).
func (a *NftablesRules) PostRollback(ctx context.Context, _ string) error {
	if _, err := os.Stat(nftablesMainConf); errors.Is(err, os.ErrNotExist) {
		slog.Info("nftables: PostRollback skipped — main config missing", "path", nftablesMainConf)
		return nil
	}
	out, err := a.getRunner().Run(ctx, "-f", nftablesMainConf)
	if err != nil {
		if isExecNotFound(err) {
			slog.Info("nftables: PostRollback skipped — nft binary missing")
			return nil
		}
		return fmt.Errorf("nft -f %s: %w (output: %s)", nftablesMainConf, err, string(out))
	}
	return nil
}

// isExecNotFound reports whether err indicates the binary was not found.
func isExecNotFound(err error) bool {
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return errors.Is(execErr.Err, exec.ErrNotFound)
	}
	return false
}
