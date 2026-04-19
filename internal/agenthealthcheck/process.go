// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"os"
	"path/filepath"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// checkProcess scans /proc/*/comm for the named process. Match is on basename
// only (the kernel truncates comm to 15 chars).
func checkProcess(name string, c *lmdmv1.ProcessCheck) HealthCheckResult {
	target := strings.TrimSpace(c.GetProcessName())
	if target == "" {
		return HealthCheckResult{Name: name, Passed: false, Detail: "empty process_name"}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return HealthCheckResult{Name: name, Passed: false, Detail: "cannot read /proc: " + err.Error()}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconvAtoi(e.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == target {
			return HealthCheckResult{Name: name, Passed: true, Detail: "found pid " + e.Name()}
		}
	}
	return HealthCheckResult{Name: name, Passed: false, Detail: "process not found"}
}

// strconvAtoi is a tiny inline wrapper to avoid importing strconv twice.
func strconvAtoi(s string) (int, error) {
	if s == "" {
		return 0, os.ErrInvalid
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, os.ErrInvalid
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
