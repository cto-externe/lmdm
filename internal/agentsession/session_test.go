// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentsession

import (
	"context"
	"errors"
	"testing"
)

// fakeRunner is a test double for CommandRunner.
// outputs and errs are keyed by command name.
type fakeRunner struct {
	outputs map[string][]byte
	errs    map[string]error
}

func (f *fakeRunner) Run(_ context.Context, name string, _ ...string) ([]byte, error) {
	return f.outputs[name], f.errs[name]
}

func TestHasActiveSession_LoginctlWithSeat_ReturnsTrue(t *testing.T) {
	r := &fakeRunner{
		outputs: map[string][]byte{
			"loginctl": []byte("c1 1000 alice seat0 tty2 active\n"),
		},
		errs: map[string]error{},
	}
	c := NewCheckerWith(r)
	if !c.HasActiveSession(context.Background()) {
		t.Error("expected true when loginctl returns a session with a seat")
	}
}

func TestHasActiveSession_LoginctlEmpty_ReturnsFalse(t *testing.T) {
	r := &fakeRunner{
		outputs: map[string][]byte{
			"loginctl": []byte(""),
		},
		errs: map[string]error{},
	}
	c := NewCheckerWith(r)
	if c.HasActiveSession(context.Background()) {
		t.Error("expected false when loginctl returns empty output")
	}
}

func TestHasActiveSession_FallsBackToWho_WhenLoginctlErrors(t *testing.T) {
	r := &fakeRunner{
		outputs: map[string][]byte{
			"who": []byte("alice tty2 2026-04-21 10:30\n"),
		},
		errs: map[string]error{
			"loginctl": errors.New("loginctl: command not found"),
		},
	}
	c := NewCheckerWith(r)
	if !c.HasActiveSession(context.Background()) {
		t.Error("expected true when loginctl errors but who returns a session")
	}
}

func TestHasActiveSession_BothFail_ReturnsFalse(t *testing.T) {
	r := &fakeRunner{
		outputs: map[string][]byte{},
		errs: map[string]error{
			"loginctl": errors.New("loginctl: command not found"),
			"who":      errors.New("who: command not found"),
		},
	}
	c := NewCheckerWith(r)
	if c.HasActiveSession(context.Background()) {
		t.Error("expected false when both loginctl and who fail")
	}
}
