// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"testing"
)

func TestRunner_CheckNATSReachable_NilProber_Fails(t *testing.T) {
	r := NewRunner(nil, nil)
	res := r.checkNATSReachable(context.Background())
	if res.Passed {
		t.Fatalf("want failed when prober nil")
	}
	if res.Name != "system.nats_reachable" {
		t.Errorf("name: %s", res.Name)
	}
}

func TestRunner_CheckNATSReachable_OK(t *testing.T) {
	r := NewRunner(&fakeNATSProber{}, nil)
	res := r.checkNATSReachable(context.Background())
	if !res.Passed {
		t.Fatalf("want passed: %s", res.Detail)
	}
}

func TestRunner_CheckSystemdServiceActive_HappyPath(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.stdout["systemctl is-active dbus"] = []byte("active\n")
	cmd.exit["systemctl is-active dbus"] = 0
	r := NewRunner(nil, cmd)
	res := r.checkSystemdServiceActive(context.Background(), "dbus", "system.dbus_active", false)
	if !res.Passed {
		t.Fatalf("want passed: %s", res.Detail)
	}
	if res.Name != "system.dbus_active" {
		t.Errorf("name: %s", res.Name)
	}
}

func TestRunner_CheckSystemdServiceActive_Inactive_Fails(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.stdout["systemctl is-active dbus"] = []byte("inactive\n")
	cmd.exit["systemctl is-active dbus"] = 3
	r := NewRunner(nil, cmd)
	res := r.checkSystemdServiceActive(context.Background(), "dbus", "system.dbus_active", false)
	if res.Passed {
		t.Fatalf("want failed when inactive")
	}
}

func TestRunner_CheckSystemdServiceActive_NoRunner_Fails(t *testing.T) {
	r := NewRunner(nil, nil)
	res := r.checkSystemdServiceActive(context.Background(), "dbus", "system.dbus_active", false)
	if res.Passed {
		t.Fatalf("want failed without runner")
	}
}

func TestRunner_CheckSSH_PassesIfMissing(t *testing.T) {
	cmd := newFakeCommandRunner()
	// both ssh and sshd return exit 4 with empty stdout (unit not found)
	cmd.exit["systemctl is-active ssh"] = 4
	cmd.exit["systemctl is-active sshd"] = 4
	r := NewRunner(nil, cmd)
	res := r.checkSSH(context.Background())
	if !res.Passed {
		t.Fatalf("want passed (skip-as-pass) when both ssh units missing, got: %+v", res)
	}
}

func TestRunner_CheckNetworking_NetworkManagerOnly(t *testing.T) {
	cmd := newFakeCommandRunner()
	// systemd-networkd inactive
	cmd.stdout["systemctl is-active systemd-networkd"] = []byte("inactive\n")
	cmd.exit["systemctl is-active systemd-networkd"] = 3
	// NetworkManager active
	cmd.stdout["systemctl is-active NetworkManager"] = []byte("active\n")
	cmd.exit["systemctl is-active NetworkManager"] = 0
	r := NewRunner(nil, cmd)
	res := r.checkNetworking(context.Background())
	if !res.Passed {
		t.Fatalf("want passed when NetworkManager active: %s", res.Detail)
	}
}

func TestRunner_CheckNetworking_BothInactive_Fails(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.stdout["systemctl is-active systemd-networkd"] = []byte("inactive\n")
	cmd.exit["systemctl is-active systemd-networkd"] = 3
	cmd.stdout["systemctl is-active NetworkManager"] = []byte("inactive\n")
	cmd.exit["systemctl is-active NetworkManager"] = 3
	r := NewRunner(nil, cmd)
	res := r.checkNetworking(context.Background())
	if res.Passed {
		t.Fatalf("want failed when both inactive")
	}
}
