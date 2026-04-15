// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"strings"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

const osReleaseUbuntu = `NAME="Ubuntu"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04.1 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
`

const osReleaseFedora = `NAME="Fedora Linux"
VERSION="40 (Workstation Edition)"
ID=fedora
VERSION_ID=40
PLATFORM_ID="platform:f40"
`

func TestParseOSReleaseUbuntu(t *testing.T) {
	os := parseOSRelease(strings.NewReader(osReleaseUbuntu))
	if os.Family != lmdmv1.OSFamily_OS_FAMILY_DEBIAN {
		t.Errorf("Family = %v, want DEBIAN", os.Family)
	}
	if os.Name != "ubuntu" || os.Version != "24.04" || os.Codename != "noble" {
		t.Errorf("OSInfo = %+v", os)
	}
}

func TestParseOSReleaseFedora(t *testing.T) {
	os := parseOSRelease(strings.NewReader(osReleaseFedora))
	if os.Family != lmdmv1.OSFamily_OS_FAMILY_RHEL {
		t.Errorf("Family = %v, want RHEL", os.Family)
	}
	if os.Name != "fedora" {
		t.Errorf("Name = %q", os.Name)
	}
}

func TestOSFamilyFromIDs(t *testing.T) {
	cases := []struct {
		id, idLike string
		want       lmdmv1.OSFamily
	}{
		{"debian", "", lmdmv1.OSFamily_OS_FAMILY_DEBIAN},
		{"ubuntu", "debian", lmdmv1.OSFamily_OS_FAMILY_DEBIAN},
		{"mint", "ubuntu debian", lmdmv1.OSFamily_OS_FAMILY_DEBIAN},
		{"rhel", "", lmdmv1.OSFamily_OS_FAMILY_RHEL},
		{"fedora", "", lmdmv1.OSFamily_OS_FAMILY_RHEL},
		{"almalinux", "rhel", lmdmv1.OSFamily_OS_FAMILY_RHEL},
		{"nixos", "", lmdmv1.OSFamily_OS_FAMILY_NIXOS},
		{"gentoo", "", lmdmv1.OSFamily_OS_FAMILY_UNSPECIFIED},
	}
	for _, c := range cases {
		got := osFamilyFromIDs(c.id, c.idLike)
		if got != c.want {
			t.Errorf("osFamilyFromIDs(%q, %q) = %v, want %v", c.id, c.idLike, got, c.want)
		}
	}
}
