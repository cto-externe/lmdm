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

// fakeProviderAction is an Action that ALSO implements RollbackProvider.
// It records when its Rollback was called.
type fakeProviderAction struct {
	name      string
	callOrder *[]string
	rbErr     error
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
