// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package distro

import "testing"

func TestNewPatchManagerDebian(t *testing.T) {
	pm, err := NewPatchManager("debian")
	if err != nil { t.Fatal(err) }
	if pm.Family() != "debian" { t.Errorf("Family() = %q", pm.Family()) }
}

func TestNewPatchManagerRHEL(t *testing.T) {
	pm, err := NewPatchManager("rhel")
	if err != nil { t.Fatal(err) }
	if pm.Family() != "rhel" { t.Errorf("Family() = %q", pm.Family()) }
}

func TestNewPatchManagerNixOS(t *testing.T) {
	pm, err := NewPatchManager("nixos")
	if err != nil { t.Fatal(err) }
	if pm.Family() != "nixos" { t.Errorf("Family() = %q", pm.Family()) }
}

func TestNewPatchManagerUnsupported(t *testing.T) {
	_, err := NewPatchManager("gentoo")
	if err == nil { t.Fatal("must error on unsupported family") }
}
