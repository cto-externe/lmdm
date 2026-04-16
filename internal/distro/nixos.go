// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package distro

import (
	"context"
	"errors"
)

// ErrNixOSNotSupported is returned by all NixOSPatchManager methods.
var ErrNixOSNotSupported = errors.New("distro: NixOS uses declarative configuration — use profile-based management instead")

// NixOSPatchManager is a stub. NixOS patch management is handled by the
// profile engine (nixos-rebuild switch), not imperative package upgrades.
type NixOSPatchManager struct{}

// Family implements PatchManager.
func (n *NixOSPatchManager) Family() string { return "nixos" }

// RefreshSources is not supported on NixOS.
func (n *NixOSPatchManager) RefreshSources(_ context.Context) error { return ErrNixOSNotSupported }

// DetectUpdates is not supported on NixOS.
func (n *NixOSPatchManager) DetectUpdates(_ context.Context) ([]Update, bool, error) {
	return nil, false, ErrNixOSNotSupported
}

// ApplyUpdates is not supported on NixOS.
func (n *NixOSPatchManager) ApplyUpdates(_ context.Context, _ PatchFilter) (string, error) {
	return "", ErrNixOSNotSupported
}
