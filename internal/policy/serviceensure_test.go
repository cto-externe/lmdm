// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"testing"
)

func TestNewServiceEnsureValid(t *testing.T) {
	params := map[string]any{
		"enabled":  []any{"chronyd"},
		"disabled": []any{"systemd-timesyncd", "ntpd"},
	}
	a, err := NewServiceEnsure(params)
	if err != nil {
		t.Fatalf("NewServiceEnsure: %v", err)
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestNewServiceEnsureBadType(t *testing.T) {
	_, err := NewServiceEnsure(map[string]any{"enabled": 42})
	if err == nil {
		t.Fatal("must reject non-list enabled")
	}
}
