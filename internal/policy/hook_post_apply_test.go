// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunPostApply_EmptyCmd_NoOp(t *testing.T) {
	out, err := runPostApply(context.Background(), "", 60*time.Second)
	if err != nil {
		t.Errorf("empty cmd should be no-op, got err=%v", err)
	}
	if out != "" {
		t.Errorf("empty cmd should return no output, got %q", out)
	}
}

func TestRunPostApply_SuccessfulCommand_ReturnsOutput(t *testing.T) {
	out, err := runPostApply(context.Background(), "echo lmdm-hook-ok", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "lmdm-hook-ok") {
		t.Errorf("expected hook output, got %q", out)
	}
}

func TestRunPostApply_FailingCommand_ReturnsError(t *testing.T) {
	_, err := runPostApply(context.Background(), "sh -c 'exit 3'", 5*time.Second)
	if err == nil {
		t.Fatal("non-zero exit must surface as error")
	}
}

func TestRunPostApply_Timeout_Kills(t *testing.T) {
	_, err := runPostApply(context.Background(), "sleep 5", 100*time.Millisecond)
	if err == nil {
		t.Fatal("timeout must kill command and return error")
	}
}
