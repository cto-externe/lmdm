// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package distro

import (
	"strings"
	"testing"
)

const aptListFixture = `Listing...
openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.16 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
libssl3/jammy-updates,jammy-security 3.0.2-0ubuntu1.16 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
curl/jammy-updates 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]
`

func TestParseAptListUpgradable(t *testing.T) {
	updates := parseAptList(strings.NewReader(aptListFixture))
	if len(updates) != 3 {
		t.Fatalf("len = %d, want 3", len(updates))
	}
	if updates[0].Name != "openssl" || !updates[0].Security {
		t.Errorf("[0] = %+v", updates[0])
	}
	if updates[0].CurrentVersion != "3.0.2-0ubuntu1.15" {
		t.Errorf("current = %q", updates[0].CurrentVersion)
	}
	if updates[0].AvailableVersion != "3.0.2-0ubuntu1.16" {
		t.Errorf("available = %q", updates[0].AvailableVersion)
	}
	if updates[2].Name != "curl" || updates[2].Security {
		t.Errorf("[2] should NOT be security: %+v", updates[2])
	}
	for _, u := range updates {
		if u.Source != "apt" {
			t.Errorf("Source = %q", u.Source)
		}
	}
}

func TestParseAptListEmpty(t *testing.T) {
	if len(parseAptList(strings.NewReader("Listing...\n"))) != 0 {
		t.Error("empty → 0")
	}
}

func TestDebianUpgradeArgsAll(t *testing.T) {
	args := debianUpgradeArgs(PatchFilter{})
	if len(args) != 3 || args[1] != "upgrade" {
		t.Errorf("args = %v", args)
	}
}

func TestDebianUpgradeArgsSpecific(t *testing.T) {
	args := debianUpgradeArgs(PatchFilter{IncludePackages: []string{"openssl", "curl"}})
	if len(args) != 6 || args[1] != "install" || args[2] != "--only-upgrade" {
		t.Errorf("args = %v", args)
	}
}
