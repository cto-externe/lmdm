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

// DebianPatchManager uses apt/dpkg for Debian, Ubuntu, and Mint.
type DebianPatchManager struct{}

// Family implements PatchManager.
func (d *DebianPatchManager) Family() string { return "debian" }

// RefreshSources runs apt-get update.
func (d *DebianPatchManager) RefreshSources(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "apt-get", "update", "-qq").CombinedOutput() //nolint:gosec
	if err != nil {
		return fmt.Errorf("apt-get update: %s: %w", string(out), err)
	}
	return nil
}

// DetectUpdates lists upgradable packages via apt.
func (d *DebianPatchManager) DetectUpdates(ctx context.Context) ([]Update, bool, error) {
	_ = d.RefreshSources(ctx) // best-effort
	out, err := exec.CommandContext(ctx, "apt", "list", "--upgradable", "-q").Output() //nolint:gosec
	if err != nil {
		return nil, false, fmt.Errorf("apt list: %w", err)
	}
	updates := parseAptList(bytes.NewReader(out))
	reboot := debianRebootRequired()
	return updates, reboot, nil
}

// ApplyUpdates installs pending updates via apt-get.
func (d *DebianPatchManager) ApplyUpdates(ctx context.Context, f PatchFilter) (string, error) {
	_ = d.RefreshSources(ctx)
	args := debianUpgradeArgs(f)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func debianUpgradeArgs(f PatchFilter) []string {
	if len(f.IncludePackages) > 0 {
		return append([]string{"apt-get", "install", "--only-upgrade", "-y"}, f.IncludePackages...)
	}
	return []string{"apt-get", "upgrade", "-y"}
}

func parseAptList(r io.Reader) []Update {
	var out []Update
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Listing") || line == "" {
			continue
		}
		if u, ok := parseAptLine(line); ok {
			out = append(out, u)
		}
	}
	return out
}

func parseAptLine(line string) (Update, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return Update{}, false
	}
	nameSource := fields[0]
	slashIdx := strings.IndexByte(nameSource, '/')
	if slashIdx < 0 {
		return Update{}, false
	}
	name := nameSource[:slashIdx]
	sources := nameSource[slashIdx+1:]
	available := fields[1]
	old := strings.TrimSuffix(fields[len(fields)-1], "]")
	security := strings.Contains(sources, "-security")
	return Update{Name: name, CurrentVersion: old, AvailableVersion: available, Security: security, Source: "apt"}, true
}

func debianRebootRequired() bool {
	_, err := os.Stat("/var/run/reboot-required")
	return err == nil
}
