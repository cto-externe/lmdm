// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package distro

import (
	"strings"
	"testing"
)

const dnfCheckUpdateFixture = `
openssl.x86_64                  3.0.7-27.el9_4         baseos-updates
openssl-libs.x86_64             3.0.7-27.el9_4         baseos-updates
curl.x86_64                     7.76.1-29.el9_4        baseos-security
kernel.x86_64                   5.14.0-427.20.1.el9_4  baseos-updates
`

func TestParseDnfCheckUpdate(t *testing.T) {
	updates := parseDnfCheckUpdate(strings.NewReader(dnfCheckUpdateFixture))
	if len(updates) != 4 {
		t.Fatalf("len = %d, want 4", len(updates))
	}
	if updates[0].Name != "openssl" || updates[0].AvailableVersion != "3.0.7-27.el9_4" {
		t.Errorf("[0] = %+v", updates[0])
	}
	if updates[0].Security {
		t.Error("openssl from baseos-updates NOT security")
	}
	if !updates[2].Security {
		t.Error("curl from baseos-security SHOULD be security")
	}
	for _, u := range updates {
		if u.Source != "dnf" {
			t.Errorf("Source = %q", u.Source)
		}
	}
}

func TestParseDnfCheckUpdateEmpty(t *testing.T) {
	if len(parseDnfCheckUpdate(strings.NewReader(""))) != 0 {
		t.Error("empty → 0")
	}
}

func TestRHELUpgradeArgsAll(t *testing.T) {
	args := rhelUpgradeArgs(PatchFilter{})
	if len(args) != 3 || args[0] != "dnf" {
		t.Errorf("args = %v", args)
	}
}

func TestRHELUpgradeArgsSecurity(t *testing.T) {
	args := rhelUpgradeArgs(PatchFilter{SecurityOnly: true})
	if len(args) != 4 || args[2] != "--security" {
		t.Errorf("args = %v", args)
	}
}

func TestRHELUpgradeArgsSpecific(t *testing.T) {
	args := rhelUpgradeArgs(PatchFilter{IncludePackages: []string{"openssl"}})
	if len(args) != 4 || args[3] != "openssl" {
		t.Errorf("args = %v", args)
	}
}
