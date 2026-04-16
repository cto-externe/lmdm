// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
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
