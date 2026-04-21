// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeProviderAction is an Action that ALSO implements RollbackProvider and
// optionally PostRollbackProvider. It records phase-tagged events into callOrder.
type fakeProviderAction struct {
	name         string
	callOrder    *[]string
	rbErr        error
	postRbErr    error
	withPostPhase bool // if true, also implement PostRollbackProvider
}

func (f *fakeProviderAction) Validate() error                            { return nil }
func (f *fakeProviderAction) Snapshot(_ context.Context, _ string) error { return nil }
func (f *fakeProviderAction) Apply(_ context.Context) error              { return nil }
func (f *fakeProviderAction) Verify(_ context.Context) (bool, string, error) {
	return true, "", nil
}

func (f *fakeProviderAction) Rollback(_ context.Context, _ string) error {
	*f.callOrder = append(*f.callOrder, f.name)
	return f.rbErr
}

// fakePostAction implements both RollbackProvider and PostRollbackProvider,
// tagging each call with a phase prefix ("pre:" / "post:").
type fakePostAction struct {
	name      string
	callOrder *[]string
}

func (f *fakePostAction) Validate() error                            { return nil }
func (f *fakePostAction) Snapshot(_ context.Context, _ string) error { return nil }
func (f *fakePostAction) Apply(_ context.Context) error              { return nil }
func (f *fakePostAction) Verify(_ context.Context) (bool, string, error) {
	return true, "", nil
}

func (f *fakePostAction) Rollback(_ context.Context, _ string) error {
	*f.callOrder = append(*f.callOrder, "pre:"+f.name)
	return nil
}

func (f *fakePostAction) PostRollback(_ context.Context, _ string) error {
	*f.callOrder = append(*f.callOrder, "post:"+f.name)
	return nil
}

// fakeCentralMarker records when the central Rollback runs by using a snapDir
// file convention (sysctl.json with empty map, so Rollback executes cheaply).
// We detect it via a sentinel file written in the snapDir before the call.

// fakePlainAction does NOT implement RollbackProvider.
type fakePlainAction struct{ name string }

func (f *fakePlainAction) Validate() error                            { return nil }
func (f *fakePlainAction) Snapshot(_ context.Context, _ string) error { return nil }
func (f *fakePlainAction) Apply(_ context.Context) error              { return nil }
func (f *fakePlainAction) Verify(_ context.Context) (bool, string, error) {
	return true, "", nil
}

func TestRollbackWithProviders_InvokesProvidersInReverseOrder(t *testing.T) {
	var order []string
	actions := []Action{
		&fakeProviderAction{name: "A", callOrder: &order},
		&fakePlainAction{name: "Plain"}, // skipped
		&fakeProviderAction{name: "B", callOrder: &order},
		&fakeProviderAction{name: "C", callOrder: &order},
	}
	snapDir := t.TempDir()
	if err := RollbackWithProviders(context.Background(), snapDir, actions); err != nil {
		t.Fatalf("rollback returned error: %v", err)
	}
	if got, want := strings.Join(order, ","), "C,B,A"; got != want {
		t.Errorf("provider invocation order: got %q, want %q", got, want)
	}
}

func TestRollbackWithProviders_ProviderErrorsAggregateButContinue(t *testing.T) {
	var order []string
	actions := []Action{
		&fakeProviderAction{name: "A", callOrder: &order, rbErr: fmt.Errorf("boom A")},
		&fakeProviderAction{name: "B", callOrder: &order, rbErr: fmt.Errorf("boom B")},
	}
	snapDir := t.TempDir()
	err := RollbackWithProviders(context.Background(), snapDir, actions)
	if err == nil {
		t.Fatal("expected aggregated error")
	}
	if !strings.Contains(err.Error(), "boom A") || !strings.Contains(err.Error(), "boom B") {
		t.Errorf("expected both errors in message, got %q", err.Error())
	}
	if len(order) != 2 {
		t.Errorf("expected both providers invoked despite errors, got %d", len(order))
	}
}

func TestRollbackWithProviders_FallsBackToCentralForArtifacts(t *testing.T) {
	// Sanity: even with no providers, the central Rollback should run.
	// We seed a packages.json with one package "absent" so rollback would
	// try to install it — but since we don't actually want to call apt in
	// a unit test, just assert that Rollback doesn't panic when handed
	// an empty snapDir (existing behavior).
	snapDir := t.TempDir()
	// create a minimal sysctl.json so something is exercised
	_ = os.WriteFile(filepath.Join(snapDir, "sysctl.json"), []byte(`{}`), 0o600)
	if err := RollbackWithProviders(context.Background(), snapDir, nil); err != nil {
		t.Fatalf("expected nil with empty providers + minimal snapDir, got %v", err)
	}
}

// TestRollbackWithProviders_RunsPostRollbackAfterCentral verifies the three-phase
// ordering: pre-provider (Phase 1) → central (Phase 2) → post-provider (Phase 3).
// We use a file written by central rollbackFiles as the "central ran" marker.
func TestRollbackWithProviders_RunsPostRollbackAfterCentral(t *testing.T) {
	dir := t.TempDir()
	snapDir := filepath.Join(dir, "snap")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Set up a file restore so the central Rollback does observable work.
	target := filepath.Join(dir, "sentinel.conf")
	backupPath := filepath.Join(snapDir, "files", target)
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	var order []string

	// fakePostAction records "pre:X" in Rollback (Phase 1) and "post:X" in PostRollback (Phase 3).
	a1 := &fakePostAction{name: "A", callOrder: &order}
	a2 := &fakePostAction{name: "B", callOrder: &order}

	actions := []Action{a1, a2}
	if err := RollbackWithProviders(context.Background(), snapDir, actions); err != nil {
		t.Fatalf("RollbackWithProviders: %v", err)
	}

	// Phase 1 (reverse): B then A.
	// Phase 2: central (file restore — verified below).
	// Phase 3 (reverse): post:B then post:A.
	want := []string{"pre:B", "pre:A", "post:B", "post:A"}
	if got := strings.Join(order, ","); got != strings.Join(want, ",") {
		t.Errorf("phase order: got %q, want %q", got, strings.Join(want, ","))
	}

	// Central rollback must have restored the sentinel file (Phase 2 ran).
	data, err := os.ReadFile(target) //nolint:gosec
	if err != nil {
		t.Fatalf("sentinel file not restored by central Rollback: %v", err)
	}
	if string(data) != "original" {
		t.Errorf("sentinel content: %q, want 'original'", string(data))
	}
}
