// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package distro provides OS-family-specific abstractions for package
// management. The PatchManager interface allows the agent to detect and
// apply updates without knowing which package manager is underneath.
package distro

import (
	"context"
	"fmt"
)

// Update represents a single available package update.
type Update struct {
	Name             string
	CurrentVersion   string
	AvailableVersion string
	Security         bool
	Source           string // "apt", "dnf"
}

// PatchFilter controls which updates to apply.
type PatchFilter struct {
	SecurityOnly    bool
	IncludePackages []string
	ExcludePackages []string
}

// PatchManager abstracts update detection and application across distro
// families. The agent instantiates the right one at startup based on the
// detected OS family.
type PatchManager interface {
	Family() string
	RefreshSources(ctx context.Context) error
	DetectUpdates(ctx context.Context) ([]Update, bool, error)
	ApplyUpdates(ctx context.Context, filter PatchFilter) (string, error)
}

// NewPatchManager returns the PatchManager for the given OS family.
func NewPatchManager(family string) (PatchManager, error) {
	switch family {
	case "debian":
		return &DebianPatchManager{}, nil
	case "rhel":
		return &RHELPatchManager{}, nil
	case "nixos":
		return &NixOSPatchManager{}, nil
	default:
		return nil, fmt.Errorf("distro: unsupported OS family %q for patch management", family)
	}
}
