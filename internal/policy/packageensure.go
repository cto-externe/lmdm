// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PackageEnsure installs and/or removes Debian packages via apt-get.
type PackageEnsure struct {
	Present []string
	Absent  []string
}

// NewPackageEnsure constructs a PackageEnsure from the YAML params map.
func NewPackageEnsure(params map[string]any) (Action, error) {
	pe := &PackageEnsure{}
	if v, ok := params["present"]; ok {
		list, err := toStringSlice(v)
		if err != nil {
			return nil, fmt.Errorf("package_ensure.present: %w", err)
		}
		pe.Present = list
	}
	if v, ok := params["absent"]; ok {
		list, err := toStringSlice(v)
		if err != nil {
			return nil, fmt.Errorf("package_ensure.absent: %w", err)
		}
		pe.Absent = list
	}
	return pe, nil
}

// Validate checks that PackageEnsure parameters are well-formed.
func (p *PackageEnsure) Validate() error { return nil }

// Snapshot records which packages are currently installed into snapDir/packages.json.
func (p *PackageEnsure) Snapshot(ctx context.Context, snapDir string) error {
	all := append(append([]string{}, p.Present...), p.Absent...)
	state := map[string]bool{}
	for _, pkg := range all {
		out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", pkg).Output() //nolint:gosec
		state[pkg] = err == nil && strings.Contains(string(out), "install ok installed")
	}
	data, _ := json.Marshal(state)
	return os.WriteFile(filepath.Join(snapDir, "packages.json"), data, 0o600)
}

// Apply installs packages in Present and removes packages in Absent via apt-get.
func (p *PackageEnsure) Apply(ctx context.Context) error {
	if len(p.Present) > 0 {
		args := p.installArgs()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("package_ensure install: %s: %w", string(out), err)
		}
	}
	if len(p.Absent) > 0 {
		args := p.removeArgs()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("package_ensure remove: %s: %w", string(out), err)
		}
	}
	return nil
}

// Verify checks that all Present packages are installed and Absent packages are not.
func (p *PackageEnsure) Verify(ctx context.Context) (bool, string, error) {
	for _, pkg := range p.Present {
		out, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", pkg).Output() //nolint:gosec
		if err != nil || !strings.Contains(string(out), "install ok installed") {
			return false, fmt.Sprintf("package %s not installed", pkg), nil
		}
	}
	for _, pkg := range p.Absent {
		out, _ := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", pkg).Output() //nolint:gosec
		if strings.Contains(string(out), "install ok installed") {
			return false, fmt.Sprintf("package %s should be absent", pkg), nil
		}
	}
	return true, "", nil
}

func (p *PackageEnsure) installArgs() []string {
	return append([]string{"apt-get", "install", "-y"}, p.Present...)
}

func (p *PackageEnsure) removeArgs() []string {
	return append([]string{"apt-get", "remove", "-y"}, p.Absent...)
}

// toStringSlice converts a []any (from YAML unmarshal) to []string.
func toStringSlice(v any) ([]string, error) {
	raw, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list, got %T", v)
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("expected string item, got %T", item)
		}
		out = append(out, s)
	}
	return out, nil
}
