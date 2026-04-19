// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"fmt"
	"net/http"
	"time"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func checkHTTP(ctx context.Context, name string, c *lmdmv1.HTTPGetCheck, timeoutSec uint32) HealthCheckResult {
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.GetUrl(), nil)
	if err != nil {
		return HealthCheckResult{Name: name, Passed: false, Detail: err.Error()}
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return HealthCheckResult{Name: name, Passed: false, Detail: err.Error()}
	}
	defer resp.Body.Close()
	expected := int(c.GetExpectedStatus())
	if expected == 0 {
		expected = 200
	}
	if resp.StatusCode != expected {
		return HealthCheckResult{Name: name, Passed: false, Detail: fmt.Sprintf("status %d, want %d", resp.StatusCode, expected)}
	}
	return HealthCheckResult{Name: name, Passed: true}
}
