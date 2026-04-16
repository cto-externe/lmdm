// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"testing"
)

func TestNewSysctlValid(t *testing.T) {
	params := map[string]any{
		"net.ipv4.ip_forward":                "0",
		"net.ipv4.conf.all.rp_filter":        "1",
		"net.ipv4.conf.all.accept_redirects": "0",
	}
	a, err := NewSysctl(params)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	s := a.(*Sysctl)
	if len(s.Values) != 3 {
		t.Errorf("len(Values) = %d, want 3", len(s.Values))
	}
}

func TestNewSysctlEmpty(t *testing.T) {
	a, err := NewSysctl(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	s := a.(*Sysctl)
	if len(s.Values) != 0 {
		t.Error("empty params should yield empty Values")
	}
}
