// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecCommandRunner_Run_CapturesStdout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := NewExecCommandRunner()
	out, exitCode, err := r.Run(ctx, "echo", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(string(out), "hello") {
		t.Fatalf("unexpected stdout: %q", out)
	}
}

func TestExecCommandRunner_Run_ReturnsExitCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := NewExecCommandRunner()
	_, exitCode, _ := r.Run(ctx, "sh", "-c", "exit 7")
	if exitCode != 7 {
		t.Fatalf("expected exit 7, got %d", exitCode)
	}
}

func TestExecCommandRunner_Run_CommandNotFoundIsError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := NewExecCommandRunner()
	_, _, err := r.Run(ctx, "this-command-definitely-does-not-exist-42")
	if err == nil {
		t.Error("expected error when binary is missing")
	}
}
