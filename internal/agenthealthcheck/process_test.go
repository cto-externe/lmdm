// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// readSelfComm returns this process's truncated comm value (15-char limit).
func readSelfComm(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("/proc", "self", "comm"))
	if err != nil {
		t.Skipf("/proc not available: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func TestCheckProcess_FindsSelf(t *testing.T) {
	self := readSelfComm(t)
	res := checkProcess("p", &lmdmv1.ProcessCheck{ProcessName: self})
	if !res.Passed {
		t.Fatalf("want to find self (%q): %s", self, res.Detail)
	}
}

func TestCheckProcess_NotFound(t *testing.T) {
	res := checkProcess("p", &lmdmv1.ProcessCheck{ProcessName: "definitely-not-a-real-proc-xyz"})
	if res.Passed {
		t.Fatalf("want failed for unknown process")
	}
}

func TestCheckProcess_EmptyName(t *testing.T) {
	res := checkProcess("p", &lmdmv1.ProcessCheck{ProcessName: ""})
	if res.Passed {
		t.Fatalf("want failed for empty name")
	}
}

func TestStrconvAtoi(t *testing.T) {
	cases := []struct {
		in  string
		ok  bool
		out int
	}{
		{"123", true, 123},
		{"0", true, 0},
		{"", false, 0},
		{"12a", false, 0},
		{"abc", false, 0},
	}
	for _, c := range cases {
		got, err := strconvAtoi(c.in)
		if (err == nil) != c.ok {
			t.Errorf("strconvAtoi(%q) err=%v want ok=%v", c.in, err, c.ok)
			continue
		}
		if c.ok && got != c.out {
			t.Errorf("strconvAtoi(%q) = %d, want %d", c.in, got, c.out)
		}
	}
}
