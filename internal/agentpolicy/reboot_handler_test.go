// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"path/filepath"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agentsession"
	"github.com/cto-externe/lmdm/internal/agentstate"
	"github.com/cto-externe/lmdm/internal/distro"
)

// fakeSessionRunner implements agentsession.CommandRunner and returns fixed
// output for loginctl, driving HasActiveSession deterministically in tests.
type fakeSessionRunner struct {
	active bool
}

func (f *fakeSessionRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	if f.active {
		// One row with a seat column → active session.
		return []byte("1 1000 alice seat0 tty2\n"), nil
	}
	return []byte(""), nil
}

// newFakeSession builds an agentsession.Checker backed by our fake runner.
func newFakeSession(active bool) *agentsession.Checker {
	return agentsession.NewCheckerWith(&fakeSessionRunner{active: active})
}

// fakePatchManager satisfies distro.PatchManager for handler tests.
type fakePatchManager struct {
	applyOutput   string
	applyErr      error
	detectUpdates []distro.Update
	detectReboot  bool
	detectErr     error
}

func (f *fakePatchManager) Family() string { return "fake" }
func (f *fakePatchManager) RefreshSources(_ context.Context) error { return nil }
func (f *fakePatchManager) DetectUpdates(_ context.Context) ([]distro.Update, bool, error) {
	return f.detectUpdates, f.detectReboot, f.detectErr
}
func (f *fakePatchManager) ApplyUpdates(_ context.Context, _ distro.PatchFilter) (string, error) {
	return f.applyOutput, f.applyErr
}

// openTestState opens a BoltDB-backed agentstate.Store in t.TempDir.
func openTestState(t *testing.T) *agentstate.Store {
	t.Helper()
	st, err := agentstate.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestHandleReboot_Force_BypassesSessionCheck verifies that Force=true skips
// the session check and proceeds directly to reboot even when a session is active.
func TestHandleReboot_Force_BypassesSessionCheck(t *testing.T) {
	exec := &fakeRebootExecutor{}
	h := &Handler{
		deviceID:   "dev-force",
		session:    newFakeSession(true), // active session — must be bypassed
		rebootExec: exec,
		state:      openTestState(t),
	}

	cmd := &lmdmv1.RebootCommand{
		Force:              true,
		GracePeriodSeconds: 1,
		Reason:             "test-force",
	}
	h.handleRebootCommand(context.Background(), cmd)

	if !exec.rebootCalled {
		t.Error("expected reboot to be called when Force=true, even with active session")
	}
	if len(exec.broadcasts) == 0 {
		t.Error("expected at least one broadcast before reboot")
	}
}

// TestHandleReboot_NoSession_Reboots verifies that with no active session the
// handler proceeds straight to reboot.
func TestHandleReboot_NoSession_Reboots(t *testing.T) {
	exec := &fakeRebootExecutor{}
	h := &Handler{
		deviceID:   "dev-nosession",
		session:    newFakeSession(false), // no active session
		rebootExec: exec,
		state:      openTestState(t),
	}

	cmd := &lmdmv1.RebootCommand{
		Force:              false,
		GracePeriodSeconds: 1,
		Reason:             "test-nosession",
	}
	h.handleRebootCommand(context.Background(), cmd)

	if !exec.rebootCalled {
		t.Error("expected reboot to be called when no active session")
	}
}

// TestHandleReboot_UserActive_Defers_UnderLimit verifies that when a session
// is active and the defer count is below the limit, the reboot is deferred.
func TestHandleReboot_UserActive_Defers_UnderLimit(t *testing.T) {
	exec := &fakeRebootExecutor{}
	st := openTestState(t)
	h := &Handler{
		deviceID:      "dev-defer",
		session:       newFakeSession(true), // active session
		rebootExec:    exec,
		state:         st,
		maxDeferCount: 3,
	}

	cmd := &lmdmv1.RebootCommand{
		Force:              false,
		GracePeriodSeconds: 1,
		Reason:             "test-defer",
	}
	h.handleRebootCommand(context.Background(), cmd)

	if exec.rebootCalled {
		t.Error("reboot must NOT be called when deferred under limit")
	}

	// Verify defer counter was incremented to 1.
	state, err := st.GetRebootDefer()
	if err != nil {
		t.Fatalf("GetRebootDefer: %v", err)
	}
	if state.Count != 1 {
		t.Errorf("defer count = %d, want 1", state.Count)
	}
}

// TestHandleReboot_UserActive_ReachesMaxDefer_Forces verifies that when the
// defer count reaches maxDeferCount the handler forces the reboot.
func TestHandleReboot_UserActive_ReachesMaxDefer_Forces(t *testing.T) {
	exec := &fakeRebootExecutor{}
	st := openTestState(t)

	// Pre-seed defer count at maxDefer-1 so this call tips it over.
	if err := st.SetRebootDefer(agentstate.RebootDeferState{Count: 2}); err != nil {
		t.Fatalf("SetRebootDefer: %v", err)
	}

	h := &Handler{
		deviceID:      "dev-maxdefer",
		session:       newFakeSession(true), // active session
		rebootExec:    exec,
		state:         st,
		maxDeferCount: 3,
	}

	cmd := &lmdmv1.RebootCommand{
		Force:              false,
		GracePeriodSeconds: 1,
		Reason:             "test-max",
	}
	h.handleRebootCommand(context.Background(), cmd)

	if !exec.rebootCalled {
		t.Error("expected forced reboot when max defer count reached")
	}

	// Defer state must be cleared after forced reboot.
	state, err := st.GetRebootDefer()
	if err != nil {
		t.Fatalf("GetRebootDefer: %v", err)
	}
	if state.Count != 0 {
		t.Errorf("defer count after forced reboot = %d, want 0", state.Count)
	}
}

// TestHandleApplyPatches_ChainsReboot_WhenImmediateAfterApply_AndRebootRequired
// verifies that a RebootPolicy of "immediate_after_apply" with reboot_required=true
// causes handleApplyPatches to chain a reboot.
func TestHandleApplyPatches_ChainsReboot_WhenImmediateAfterApply_AndRebootRequired(t *testing.T) {
	exec := &fakeRebootExecutor{}
	pm := &fakePatchManager{
		detectReboot: true, // kernel update pending → reboot required
	}
	h := &Handler{
		deviceID:   "dev-chain",
		pm:         pm,
		session:    newFakeSession(false), // no active session → reboot proceeds
		rebootExec: exec,
		state:      openTestState(t),
	}

	cmd := &lmdmv1.ApplyPatchesCommand{
		RebootPolicy: "immediate_after_apply",
	}
	h.handleApplyPatches(context.Background(), cmd)

	if !exec.rebootCalled {
		t.Error("expected chained reboot when reboot_policy=immediate_after_apply and reboot_required=true")
	}
}
