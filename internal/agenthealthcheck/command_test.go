// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"errors"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func TestCheckCommand_HappyPath(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.stdout["sh -c true"] = []byte("")
	cmd.exit["sh -c true"] = 0
	res := checkCommand(context.Background(), cmd, "c", &lmdmv1.CommandCheck{Command: "true", ExpectedExit: 0}, 5)
	if !res.Passed {
		t.Fatalf("want passed: %s", res.Detail)
	}
}

func TestCheckCommand_WrongExit(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.exit["sh -c false"] = 1
	res := checkCommand(context.Background(), cmd, "c", &lmdmv1.CommandCheck{Command: "false", ExpectedExit: 0}, 5)
	if res.Passed {
		t.Fatalf("want failed on exit 1")
	}
}

func TestCheckCommand_ExpectsNonZero(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.exit["sh -c false"] = 1
	res := checkCommand(context.Background(), cmd, "c", &lmdmv1.CommandCheck{Command: "false", ExpectedExit: 1}, 5)
	if !res.Passed {
		t.Fatalf("want passed when actual matches expected non-zero")
	}
}

func TestCheckCommand_NilRunner(t *testing.T) {
	res := checkCommand(context.Background(), nil, "c", &lmdmv1.CommandCheck{Command: "true"}, 5)
	if res.Passed {
		t.Fatalf("want failed without runner")
	}
}

func TestCheckCommand_RunnerError(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.err["sh -c whatever"] = errors.New("exec denied")
	res := checkCommand(context.Background(), cmd, "c", &lmdmv1.CommandCheck{Command: "whatever"}, 5)
	if res.Passed {
		t.Fatalf("want failed on exec error")
	}
}
