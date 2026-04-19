// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"fmt"
	"time"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agenthealth"
)

func checkCommand(ctx context.Context, runner agenthealth.CommandRunner, name string, c *lmdmv1.CommandCheck, timeoutSec uint32) HealthCheckResult {
	if runner == nil {
		return HealthCheckResult{Name: name, Passed: false, Detail: "no command runner"}
	}
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	expected := int(c.GetExpectedExit())
	_, exit, err := runner.Run(ctx, "sh", "-c", c.GetCommand())
	if err != nil {
		return HealthCheckResult{Name: name, Passed: false, Detail: "exec error: " + err.Error()}
	}
	if exit != expected {
		return HealthCheckResult{Name: name, Passed: false, Detail: fmt.Sprintf("exit %d, want %d", exit, expected)}
	}
	return HealthCheckResult{Name: name, Passed: true}
}
