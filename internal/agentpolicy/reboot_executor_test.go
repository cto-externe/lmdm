// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"testing"
	"time"
)

// fakeRebootExecutor records calls for use in unit tests.
type fakeRebootExecutor struct {
	broadcasts   []string
	rebootCalled bool
	sleeps       []time.Duration
	rebootErr    error
}

func (f *fakeRebootExecutor) Broadcast(_ context.Context, msg string) error {
	f.broadcasts = append(f.broadcasts, msg)
	return nil
}

func (f *fakeRebootExecutor) Reboot(_ context.Context) error {
	f.rebootCalled = true
	return f.rebootErr
}

func (f *fakeRebootExecutor) Sleep(_ context.Context, d time.Duration) error {
	f.sleeps = append(f.sleeps, d)
	return nil
}

func TestSystemdRebootExecutor_Broadcast_EmptyMessage_NoOp(t *testing.T) {
	exec := &systemdRebootExecutor{}
	err := exec.Broadcast(context.Background(), "")
	if err != nil {
		t.Errorf("expected nil error for empty broadcast, got %v", err)
	}
}

func TestSystemdRebootExecutor_Sleep_Elapses(t *testing.T) {
	exec := &systemdRebootExecutor{}
	start := time.Now()
	err := exec.Sleep(context.Background(), 50*time.Millisecond)
	elapsed := time.Since(start)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if elapsed < 40*time.Millisecond {
		t.Errorf("sleep returned too early: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("sleep took too long: %v", elapsed)
	}
}

func TestSystemdRebootExecutor_Sleep_CancelledContext_Returns(t *testing.T) {
	exec := &systemdRebootExecutor{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := exec.Sleep(ctx, 10*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Error("expected non-nil error when context is cancelled")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("cancelled sleep took too long: %v", elapsed)
	}
}
