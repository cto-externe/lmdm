// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// RebootExecutor is the shell-out layer for the reboot flow.
// Tests inject a fake so unit tests don't need CAP_SYS_BOOT.
type RebootExecutor interface {
	// Broadcast sends a wall message to all logged-in users. An empty
	// message is a no-op. Errors are non-fatal (logged and swallowed).
	Broadcast(ctx context.Context, message string) error
	// Reboot requests an OS-level shutdown+reboot. Expected to NOT return
	// on success (the kernel takes over); the error is for the "no
	// permission" / "systemd unavailable" cases.
	Reboot(ctx context.Context) error
	// Sleep waits for d or until ctx is cancelled. Separated from time.Sleep
	// so tests can fast-forward.
	Sleep(ctx context.Context, d time.Duration) error
}

// NewRebootExecutor returns the real executor using wall + systemctl.
func NewRebootExecutor() RebootExecutor { return &systemdRebootExecutor{} }

type systemdRebootExecutor struct{}

func (s *systemdRebootExecutor) Broadcast(ctx context.Context, msg string) error {
	if strings.TrimSpace(msg) == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "wall") //nolint:gosec
	cmd.Stdin = strings.NewReader(msg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Warn("reboot broadcast failed (non-fatal)", "err", err, "out", string(out))
	}
	return nil
}

func (s *systemdRebootExecutor) Reboot(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "systemctl", "reboot").CombinedOutput() //nolint:gosec
	if err != nil {
		return fmt.Errorf("systemctl reboot: %w (output: %s)", err, string(out))
	}
	return nil
}

func (s *systemdRebootExecutor) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
