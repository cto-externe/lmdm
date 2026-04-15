// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"strings"
	"testing"
)

// Simulated `systemctl list-units --type=service --all --no-pager --plain --no-legend` output.
const systemctlFixture = `  chronyd.service                    loaded active running Network Time Service
  ssh.service                        loaded active running OpenBSD Secure Shell server
  cups.service                       loaded inactive dead  CUPS Scheduler
  dbus.socket                        loaded active running D-Bus System Message Bus Socket
  fake.service                       not-found inactive dead  fake
`

func TestParseSystemctlList(t *testing.T) {
	svcs := parseSystemctlList(strings.NewReader(systemctlFixture))
	// Only .service entries — 4 of them including "not-found" ones.
	if len(svcs) != 4 {
		t.Fatalf("len(svcs) = %d, want 4", len(svcs))
	}
	if svcs[0].Name != "chronyd.service" {
		t.Errorf("svcs[0].Name = %q", svcs[0].Name)
	}
	if svcs[0].LoadState != "loaded" || svcs[0].ActiveState != "active" || svcs[0].SubState != "running" {
		t.Errorf("svcs[0] states = %s/%s/%s", svcs[0].LoadState, svcs[0].ActiveState, svcs[0].SubState)
	}
	if svcs[0].Description != "Network Time Service" {
		t.Errorf("svcs[0].Description = %q", svcs[0].Description)
	}
}
