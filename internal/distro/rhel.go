// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package distro

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// RHELPatchManager uses dnf for RHEL, AlmaLinux, Rocky, and Fedora.
type RHELPatchManager struct{}

// Family implements PatchManager.
func (r *RHELPatchManager) Family() string { return "rhel" }

// RefreshSources runs dnf makecache.
func (r *RHELPatchManager) RefreshSources(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "dnf", "makecache", "--quiet").CombinedOutput() //nolint:gosec
	if err != nil {
		return fmt.Errorf("dnf makecache: %s: %w", string(out), err)
	}
	return nil
}

// DetectUpdates lists upgradable packages via dnf check-update.
func (r *RHELPatchManager) DetectUpdates(ctx context.Context) ([]Update, bool, error) {
	_ = r.RefreshSources(ctx)
	// dnf check-update exits 100 if updates available, 0 if up-to-date.
	out, err := exec.CommandContext(ctx, "dnf", "check-update", "--quiet").Output() //nolint:gosec
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 100 {
			// Exit 100 = updates available, parse the output.
		} else {
			return nil, false, fmt.Errorf("dnf check-update: %w", err)
		}
	}
	updates := parseDnfCheckUpdate(bytes.NewReader(out))
	reboot := rhelRebootRequired(ctx)
	return updates, reboot, nil
}

// ApplyUpdates installs pending updates via dnf upgrade.
func (r *RHELPatchManager) ApplyUpdates(ctx context.Context, f PatchFilter) (string, error) {
	_ = r.RefreshSources(ctx)
	args := rhelUpgradeArgs(f)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec
	cmd.Env = os.Environ()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func rhelUpgradeArgs(f PatchFilter) []string {
	if len(f.IncludePackages) > 0 {
		return append([]string{"dnf", "upgrade", "-y"}, f.IncludePackages...)
	}
	if f.SecurityOnly {
		return []string{"dnf", "upgrade", "--security", "-y"}
	}
	return []string{"dnf", "upgrade", "-y"}
}

func parseDnfCheckUpdate(r io.Reader) []Update {
	var out []Update
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Obsoleting") || strings.HasPrefix(line, "Security:") {
			continue
		}
		if u, ok := parseDnfLine(line); ok {
			out = append(out, u)
		}
	}
	return out
}

func parseDnfLine(line string) (Update, bool) {
	// "openssl.x86_64   3.0.7-27.el9_4  baseos-updates"
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return Update{}, false
	}
	nameArch := fields[0]
	dotIdx := strings.LastIndexByte(nameArch, '.')
	if dotIdx < 0 {
		return Update{}, false
	}
	name := nameArch[:dotIdx]
	available := fields[1]
	repo := fields[2]
	security := strings.Contains(strings.ToLower(repo), "security")
	return Update{Name: name, AvailableVersion: available, Security: security, Source: "dnf"}, true
}

func rhelRebootRequired(ctx context.Context) bool {
	err := exec.CommandContext(ctx, "needs-restarting", "-r").Run() //nolint:gosec
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return true
		}
	}
	return false
}
