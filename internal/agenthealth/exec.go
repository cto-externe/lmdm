// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agenthealth collects hardware health from the host (SMART, NVMe,
// battery, temperatures, firmware) without any NATS or network I/O.
//
// Commands are executed through a CommandRunner interface so tests can inject
// fixtures via testdata/ without depending on smartctl/nvme-cli/fwupdmgr being
// installed.
package agenthealth

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

// CommandRunner abstracts shell invocation so tests can replace it with fixtures.
type CommandRunner interface {
	// Run executes name with args and returns stdout, exit code, and error.
	// A non-zero exit code does NOT produce an error — callers inspect both
	// (smartctl in particular uses exit-code bitmasks where bit 3 = "SMART
	// error" while the JSON payload on stdout is still valid and parseable).
	// Returns a non-nil error only when the binary cannot be started
	// (missing, permission denied, etc.).
	Run(ctx context.Context, name string, args ...string) (stdout []byte, exitCode int, err error)
}

// execCommandRunner is the production CommandRunner backed by os/exec.
type execCommandRunner struct{}

// NewExecCommandRunner returns the production runner.
func NewExecCommandRunner() CommandRunner { return execCommandRunner{} }

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return stdout.Bytes(), exitErr.ExitCode(), nil
		}
		return stdout.Bytes(), -1, err
	}
	return stdout.Bytes(), 0, nil
}
