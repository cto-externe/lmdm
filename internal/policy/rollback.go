// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Rollback restores the system state from a snapshot directory. It reads
// each snapshot artifact (packages.json, services.json, sysctl.json,
// files/...) and reverses the apply. Errors are logged but do NOT stop the
// rollback — we try to restore as much as possible.
//
// If the snapshot directory is empty or doesn't contain any recognized
// artifact, Rollback is a no-op (returns nil).
func Rollback(ctx context.Context, snapDir string) error {
	var errs []string

	if err := rollbackFiles(ctx, snapDir); err != nil {
		errs = append(errs, err.Error())
	}
	if err := rollbackSysctl(ctx, snapDir); err != nil {
		errs = append(errs, err.Error())
	}
	if err := rollbackServices(ctx, snapDir); err != nil {
		errs = append(errs, err.Error())
	}
	if err := rollbackPackages(ctx, snapDir); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return fmt.Errorf("rollback: %d errors: %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// rollbackFiles restores files backed up under snapDir/files/.
func rollbackFiles(_ context.Context, snapDir string) error {
	filesDir := filepath.Join(snapDir, "files")
	if _, err := os.Stat(filesDir); os.IsNotExist(err) {
		return nil
	}
	return filepath.Walk(filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		// path is snapDir/files/etc/chrony/chrony.conf → target is /etc/chrony/chrony.conf
		rel, err := filepath.Rel(filesDir, path)
		if err != nil {
			return err
		}
		target := "/" + rel
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			return fmt.Errorf("rollback read %s: %w", path, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil { //nolint:gosec // mode 750 for restored dirs
			return err
		}
		slog.Info("rollback: restoring file", "path", target)
		return os.WriteFile(target, data, 0o644) //nolint:gosec // mode 644 for config files
	})
}

// rollbackSysctl restores sysctl values from snapDir/sysctl.json.
func rollbackSysctl(ctx context.Context, snapDir string) error {
	data, err := os.ReadFile(filepath.Join(snapDir, "sysctl.json")) //nolint:gosec // snapDir is a controlled temp path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("rollback: parse sysctl.json: %w", err)
	}
	for k, v := range values {
		arg := k + "=" + v
		if out, err := exec.CommandContext(ctx, "sysctl", "-w", arg).CombinedOutput(); err != nil { //nolint:gosec
			slog.Warn("rollback: sysctl restore failed", "key", k, "err", err, "output", string(out))
			// Continue with other keys — best effort.
		} else {
			slog.Info("rollback: restored sysctl", "key", k, "value", v)
		}
	}
	return nil
}

// rollbackServices restores service enable/disable state from snapDir/services.json.
func rollbackServices(ctx context.Context, snapDir string) error {
	data, err := os.ReadFile(filepath.Join(snapDir, "services.json")) //nolint:gosec // snapDir is a controlled temp path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var states map[string]string
	if err := json.Unmarshal(data, &states); err != nil {
		return fmt.Errorf("rollback: parse services.json: %w", err)
	}
	for svc, state := range states {
		var action string
		switch state {
		case "enabled", "enabled-runtime":
			action = "enable"
		case "disabled":
			action = "disable"
		default:
			// masked, static, etc. — skip; restoring these requires more nuance.
			slog.Info("rollback: skipping service with state", "service", svc, "state", state)
			continue
		}
		if out, err := exec.CommandContext(ctx, "systemctl", action, svc).CombinedOutput(); err != nil { //nolint:gosec
			slog.Warn("rollback: service restore failed", "service", svc, "action", action, "err", err, "output", string(out))
		} else {
			slog.Info("rollback: restored service", "service", svc, "action", action)
		}
	}
	return nil
}

// rollbackPackages restores package install/remove state from snapDir/packages.json.
func rollbackPackages(ctx context.Context, snapDir string) error {
	data, err := os.ReadFile(filepath.Join(snapDir, "packages.json")) //nolint:gosec // snapDir is a controlled temp path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var installed map[string]bool
	if err := json.Unmarshal(data, &installed); err != nil {
		return fmt.Errorf("rollback: parse packages.json: %w", err)
	}
	var toInstall, toRemove []string
	for pkg, wasInstalled := range installed {
		if wasInstalled {
			// Package was installed before apply — if apply removed it, reinstall.
			toInstall = append(toInstall, pkg)
		} else {
			// Package was NOT installed before apply — if apply installed it, remove.
			toRemove = append(toRemove, pkg)
		}
	}
	if len(toRemove) > 0 {
		args := append([]string{"apt-get", "remove", "-y"}, toRemove...)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("rollback: package remove failed", "pkgs", toRemove, "err", err, "output", string(out))
		}
	}
	if len(toInstall) > 0 {
		args := append([]string{"apt-get", "install", "-y"}, toInstall...)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("rollback: package install failed", "pkgs", toInstall, "err", err, "output", string(out))
		}
	}
	return nil
}
