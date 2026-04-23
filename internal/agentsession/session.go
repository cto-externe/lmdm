// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agentsession inspects the host for live interactive user sessions.
// The reboot handler consults Checker.HasActiveSession before proceeding;
// on true with force=false, the reboot is deferred.
package agentsession

import (
	"context"
	"os/exec"
	"strings"
)

// CommandRunner is the injectable shell runner — tests provide a fake.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Checker detects active user sessions on the host.
type Checker struct {
	runner CommandRunner
}

// NewChecker returns a Checker using the real exec.CommandContext.
func NewChecker() *Checker { return &Checker{runner: &execRunner{}} }

// NewCheckerWith returns a Checker with a custom runner (for tests).
func NewCheckerWith(r CommandRunner) *Checker { return &Checker{runner: r} }

// HasActiveSession returns true when at least one interactive session is
// active on the host. Strategy: prefer loginctl (systemd), fall back to who.
// Both return "" / empty when no session.
func (c *Checker) HasActiveSession(ctx context.Context) bool {
	// loginctl list-sessions --no-legend  (SESSION UID USER SEAT TTY)
	// A row with a non-empty SEAT column counts as interactive.
	if out, err := c.runner.Run(ctx, "loginctl", "list-sessions", "--no-legend"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[3] != "" && fields[3] != "-" {
				return true
			}
		}
		return false
	}
	// Fallback: who. Any output line = an active session.
	out, err := c.runner.Run(ctx, "who")
	if err != nil {
		return false // best-effort: if we can't tell, assume no session (safe for reboot).
	}
	return strings.TrimSpace(string(out)) != ""
}

type execRunner struct{}

func (e *execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec
}
