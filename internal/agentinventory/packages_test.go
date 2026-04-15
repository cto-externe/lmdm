// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"strings"
	"testing"
)

const dpkgFixture = `adduser	3.118ubuntu5	all	644
apt	2.4.11	amd64	4060
base-files	12ubuntu4.6	amd64	340
`

func TestParseDpkgQueryTab(t *testing.T) {
	pkgs := parseDpkgQuery(strings.NewReader(dpkgFixture))
	if len(pkgs) != 3 {
		t.Fatalf("len(pkgs) = %d, want 3", len(pkgs))
	}
	if pkgs[0].Name != "adduser" || pkgs[0].Version != "3.118ubuntu5" || pkgs[0].Arch != "all" {
		t.Errorf("pkgs[0] = %+v", pkgs[0])
	}
	if pkgs[1].InstalledSizeKb != 4060 {
		t.Errorf("pkgs[1].InstalledSizeKb = %d, want 4060", pkgs[1].InstalledSizeKb)
	}
	for _, p := range pkgs {
		if p.Source != "apt" {
			t.Errorf("pkg %q Source = %q, want apt", p.Name, p.Source)
		}
	}
}

func TestParseDpkgQuerySkipsMalformedLines(t *testing.T) {
	input := "apt\t2.4.11\tamd64\t4060\nbroken-line-no-tabs\nfoo\t1\tall\t10\n"
	pkgs := parseDpkgQuery(strings.NewReader(input))
	if len(pkgs) != 2 {
		t.Errorf("len(pkgs) = %d, want 2 (malformed line skipped)", len(pkgs))
	}
}
