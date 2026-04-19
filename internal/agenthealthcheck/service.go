// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"strings"
	"time"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agenthealth"
)

func checkService(ctx context.Context, runner agenthealth.CommandRunner, name string, c *lmdmv1.ServiceCheck, timeoutSec uint32) HealthCheckResult {
	if runner == nil {
		return HealthCheckResult{Name: name, Passed: false, Detail: "no command runner"}
	}
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	expected := strings.TrimSpace(c.GetExpectedState())
	if expected == "" {
		expected = "active"
	}
	stdout, exit, err := runner.Run(ctx, "systemctl", "is-active", c.GetServiceName())
	if err != nil {
		return HealthCheckResult{Name: name, Passed: false, Detail: "systemctl error: " + err.Error()}
	}
	state := strings.TrimSpace(string(stdout))
	passed := state == expected
	if !passed && exit == 0 && expected == "active" {
		passed = true
	}
	return HealthCheckResult{Name: name, Passed: passed, Detail: state}
}
