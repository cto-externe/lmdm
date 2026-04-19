// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"strings"
	"time"
)

const builtinTimeout = 5 * time.Second

func (r *Runner) checkNATSReachable(ctx context.Context) HealthCheckResult {
	if r.natsProber == nil {
		return HealthCheckResult{Name: "system.nats_reachable", Passed: false, Detail: "no nats prober wired"}
	}
	ctx, cancel := context.WithTimeout(ctx, builtinTimeout)
	defer cancel()
	if err := r.natsProber.AckProbe(ctx); err != nil {
		return HealthCheckResult{Name: "system.nats_reachable", Passed: false, Detail: err.Error()}
	}
	return HealthCheckResult{Name: "system.nats_reachable", Passed: true}
}

// checkSystemdServiceActive runs `systemctl is-active <name>` and returns
// passed = (exit==0 && stdout=="active"). When passIfMissing is true and
// systemctl reports the unit doesn't exist, treat it as passed (used for ssh).
func (r *Runner) checkSystemdServiceActive(ctx context.Context, name, resultName string, passIfMissing bool) HealthCheckResult {
	if r.cmdRunner == nil {
		return HealthCheckResult{Name: resultName, Passed: false, Detail: "no command runner wired"}
	}
	ctx, cancel := context.WithTimeout(ctx, builtinTimeout)
	defer cancel()
	stdout, exit, err := r.cmdRunner.Run(ctx, "systemctl", "is-active", name)
	if err != nil {
		return HealthCheckResult{Name: resultName, Passed: false, Detail: "systemctl not runnable: " + err.Error()}
	}
	state := strings.TrimSpace(string(stdout))
	if exit == 0 && state == "active" {
		return HealthCheckResult{Name: resultName, Passed: true, Detail: state}
	}
	// systemctl returns exit 4 when the unit is not loaded (i.e. doesn't exist).
	if passIfMissing && (state == "inactive" || state == "unknown" || state == "failed" || state == "") && exit == 4 {
		return HealthCheckResult{Name: resultName, Passed: true, Detail: name + " not installed"}
	}
	return HealthCheckResult{Name: resultName, Passed: false, Detail: state}
}

// checkNetworking returns passed if EITHER systemd-networkd OR NetworkManager is active.
func (r *Runner) checkNetworking(ctx context.Context) HealthCheckResult {
	a := r.checkSystemdServiceActive(ctx, "systemd-networkd", "tmp", false)
	if a.Passed {
		return HealthCheckResult{Name: "system.networking_active", Passed: true, Detail: "systemd-networkd active"}
	}
	b := r.checkSystemdServiceActive(ctx, "NetworkManager", "tmp", false)
	if b.Passed {
		return HealthCheckResult{Name: "system.networking_active", Passed: true, Detail: "NetworkManager active"}
	}
	return HealthCheckResult{Name: "system.networking_active", Passed: false, Detail: "neither systemd-networkd nor NetworkManager active"}
}

// checkSSH tries `ssh` then `sshd`. If neither service exists (likely a
// headless server without ssh installed), pass the check — ssh is optional.
func (r *Runner) checkSSH(ctx context.Context) HealthCheckResult {
	a := r.checkSystemdServiceActive(ctx, "ssh", "system.ssh_active", true)
	if a.Passed {
		return a
	}
	b := r.checkSystemdServiceActive(ctx, "sshd", "system.ssh_active", true)
	if b.Passed {
		return b
	}
	return a // return the more informative of the two failures
}
