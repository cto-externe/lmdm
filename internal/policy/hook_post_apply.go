// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"fmt"
	"os/exec"
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
func runPostApply(ctx context.Context, cmd string, timeout time.Duration) (string, error) {
	if cmd == "" {
		return "", nil
	}
	if timeout <= 0 {
		timeout = DefaultPostApplyTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(runCtx, "sh", "-c", cmd).CombinedOutput() //nolint:gosec // cmd from trusted signed profile
	if err != nil {
		return string(out), fmt.Errorf("post_apply_command %q failed: %w (output: %s)", cmd, err, string(out))
	}
	return string(out), nil
}
