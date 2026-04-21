// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// DefaultPostApplyTimeout bounds hook execution.
const DefaultPostApplyTimeout = 60 * time.Second

// runPostApply executes cmd (if non-empty) via /bin/sh -c and returns its
// combined output. An empty cmd is a no-op (nil error, empty output).
// Non-zero exit or timeout returns a wrapped error including the captured
// output so the caller can surface it in the audit log.
//
// Callers in file_content / package_ensure / file_template action types
// invoke this at the end of their Apply phase; a non-nil return triggers
// the central rollback via the executor's failure path.
func runPostApply(ctx context.Context, shellCmd string, timeout time.Duration) (string, error) {
	if shellCmd == "" {
		return "", nil
	}
	if timeout <= 0 {
		timeout = DefaultPostApplyTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Run in its own process group so the timeout kills any descendants, not just sh.
	cmd := exec.CommandContext(runCtx, "sh", "-c", shellCmd) //nolint:gosec // shellCmd from trusted signed profile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("post_apply_command %q failed: %w (output: %s)", shellCmd, err, string(out))
	}
	return string(out), nil
}
