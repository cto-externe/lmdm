// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewPackageEnsureValid(t *testing.T) {
	params := map[string]any{
		"present": []any{"chrony"},
		"absent":  []any{"ntp", "ntpdate"},
	}
	a, err := NewPackageEnsure(params)
	if err != nil {
		t.Fatalf("NewPackageEnsure: %v", err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestNewPackageEnsureEmptyIsValid(t *testing.T) {
	a, err := NewPackageEnsure(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNewPackageEnsureBadType(t *testing.T) {
	_, err := NewPackageEnsure(map[string]any{"present": "not-a-list"})
	if err == nil {
		t.Fatal("must reject non-list present")
	}
}

func TestPackageEnsureInstallCmd(t *testing.T) {
	a, _ := NewPackageEnsure(map[string]any{
		"present": []any{"chrony", "curl"},
	})
	pe := a.(*PackageEnsure)
	args := pe.installArgs()
	if len(args) != 5 || args[0] != "apt-get" || args[3] != "chrony" {
		t.Errorf("installArgs = %v", args)
	}
}

func TestPackageEnsureRemoveCmd(t *testing.T) {
	a, _ := NewPackageEnsure(map[string]any{
		"absent": []any{"ntp"},
	})
	pe := a.(*PackageEnsure)
	args := pe.removeArgs()
	if len(args) != 4 || args[0] != "apt-get" || args[3] != "ntp" {
		t.Errorf("removeArgs = %v", args)
	}
}

func TestPackageEnsure_PostApplyCommand_RunsAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "post-apply-ran")

	a, err := NewPackageEnsure(map[string]any{
		"present":            []any{"dummy-pkg"},
		"post_apply_command": "touch " + sentinel,
	})
	if err != nil {
		t.Fatal(err)
	}
	pe := a.(*PackageEnsure)
	// Stub the apt runner so no real apt-get is invoked.
	pe.runApt = func(_ context.Context, _ []string) error { return nil }

	if err := pe.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Errorf("post_apply_command did not run: sentinel file missing: %v", err)
	}
}

func TestPackageEnsure_PostApplyCommand_FailureReturnsApplyError(t *testing.T) {
	a, err := NewPackageEnsure(map[string]any{
		"present":            []any{"dummy-pkg"},
		"post_apply_command": "sh -c 'exit 1'",
	})
	if err != nil {
		t.Fatal(err)
	}
	pe := a.(*PackageEnsure)
	pe.runApt = func(_ context.Context, _ []string) error { return nil }

	if err := pe.Apply(context.Background()); err == nil {
		t.Error("Apply must return non-nil error when post_apply_command fails")
	}
}

func TestPackageEnsure_AptFailurePropagates(t *testing.T) {
	a, err := NewPackageEnsure(map[string]any{
		"present": []any{"dummy-pkg"},
	})
	if err != nil {
		t.Fatal(err)
	}
	pe := a.(*PackageEnsure)
	pe.runApt = func(_ context.Context, _ []string) error {
		return errors.New("simulated apt failure")
	}

	if err := pe.Apply(context.Background()); err == nil {
		t.Error("Apply must return non-nil error when apt runner fails")
	}
}
