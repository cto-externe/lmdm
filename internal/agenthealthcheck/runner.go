// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agenthealthcheck runs post-deployment health checks. It executes
// the 5 user-defined check types from a profile (HTTP/TCP/Process/Service/Command)
// plus 4 built-in system checks (NATS reachable, dbus active, networking
// active, ssh active). Used by the agent right after applying a profile
// during a canary deployment.
package agenthealthcheck

import (
	"context"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agenthealth"
)

// HealthCheckResult is one row of the runner output.
type HealthCheckResult struct {
	Name   string
	Passed bool
	Detail string
}

// NATSAckProber abstracts a JetStream publish-and-wait-ack round-trip used
// by the system.nats_reachable built-in check. The agent provides a real
// implementation that publishes to a probe subject and waits for the ack.
type NATSAckProber interface {
	AckProbe(ctx context.Context) error
}

// Runner orchestrates the per-check dispatch.
type Runner struct {
	natsProber NATSAckProber
	cmdRunner  agenthealth.CommandRunner
}

// NewRunner returns a Runner. Both args may be nil for partial test setups
// (the corresponding checks return Passed=false with a "missing dependency"
// detail in that case).
func NewRunner(natsProber NATSAckProber, cmdRunner agenthealth.CommandRunner) *Runner {
	return &Runner{natsProber: natsProber, cmdRunner: cmdRunner}
}

// Run dispatches each definition to the appropriate per-type function and
// returns one result per check (in input order). Unknown check types yield
// a Passed=false result with a "unknown check type" detail rather than an error.
func (r *Runner) Run(ctx context.Context, checks []*lmdmv1.HealthCheckDefinition) []HealthCheckResult {
	out := make([]HealthCheckResult, 0, len(checks))
	for _, c := range checks {
		out = append(out, r.runOne(ctx, c))
	}
	return out
}

func (r *Runner) runOne(ctx context.Context, c *lmdmv1.HealthCheckDefinition) HealthCheckResult {
	if c == nil {
		return HealthCheckResult{Name: "<nil>", Passed: false, Detail: "nil check definition"}
	}
	switch v := c.Check.(type) {
	case *lmdmv1.HealthCheckDefinition_HttpGet:
		return checkHTTP(ctx, c.Name, v.HttpGet, c.TimeoutSeconds)
	case *lmdmv1.HealthCheckDefinition_TcpConnect:
		return checkTCP(ctx, c.Name, v.TcpConnect, c.TimeoutSeconds)
	case *lmdmv1.HealthCheckDefinition_ProcessCheck:
		return checkProcess(c.Name, v.ProcessCheck)
	case *lmdmv1.HealthCheckDefinition_ServiceCheck:
		return checkService(ctx, r.cmdRunner, c.Name, v.ServiceCheck, c.TimeoutSeconds)
	case *lmdmv1.HealthCheckDefinition_CommandCheck:
		return checkCommand(ctx, r.cmdRunner, c.Name, v.CommandCheck, c.TimeoutSeconds)
	default:
		return HealthCheckResult{Name: c.Name, Passed: false, Detail: "unknown check type"}
	}
}

// RunBuiltins returns the 4 always-on system checks:
//   - system.nats_reachable
//   - system.dbus_active
//   - system.networking_active (systemd-networkd OR NetworkManager)
//   - system.ssh_active (skip-as-pass if not installed)
func (r *Runner) RunBuiltins(ctx context.Context) []HealthCheckResult {
	return []HealthCheckResult{
		r.checkNATSReachable(ctx),
		r.checkSystemdServiceActive(ctx, "dbus", "system.dbus_active", false),
		r.checkNetworking(ctx),
		r.checkSSH(ctx),
	}
}
