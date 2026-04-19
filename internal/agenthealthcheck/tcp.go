// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func checkTCP(ctx context.Context, name string, c *lmdmv1.TCPConnectCheck, timeoutSec uint32) HealthCheckResult {
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	addr := net.JoinHostPort(c.GetHost(), strconv.Itoa(int(c.GetPort())))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return HealthCheckResult{Name: name, Passed: false, Detail: err.Error()}
	}
	_ = conn.Close()
	return HealthCheckResult{Name: name, Passed: true, Detail: fmt.Sprintf("connected to %s", addr)}
}
