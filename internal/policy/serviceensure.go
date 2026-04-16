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

// ServiceEnsure enables and/or disables systemd services.
type ServiceEnsure struct {
	Enabled  []string
	Disabled []string
}

// NewServiceEnsure constructs a ServiceEnsure from the YAML params map.
func NewServiceEnsure(params map[string]any) (Action, error) {
	se := &ServiceEnsure{}
	if v, ok := params["enabled"]; ok {
		list, err := toStringSlice(v)
		if err != nil {
			return nil, fmt.Errorf("service_ensure.enabled: %w", err)
		}
		se.Enabled = list
	}
	if v, ok := params["disabled"]; ok {
		list, err := toStringSlice(v)
		if err != nil {
			return nil, fmt.Errorf("service_ensure.disabled: %w", err)
		}
		se.Disabled = list
	}
	return se, nil
}

// Validate checks that ServiceEnsure parameters are well-formed.
func (s *ServiceEnsure) Validate() error { return nil }

// Snapshot records the current enabled state of each service into snapDir/services.json.
func (s *ServiceEnsure) Snapshot(ctx context.Context, snapDir string) error {
	all := append(append([]string{}, s.Enabled...), s.Disabled...)
	state := map[string]string{}
	for _, svc := range all {
		out, _ := exec.CommandContext(ctx, "systemctl", "is-enabled", svc).Output() //nolint:gosec
		state[svc] = strings.TrimSpace(string(out))
	}
	data, _ := json.Marshal(state)
	return os.WriteFile(filepath.Join(snapDir, "services.json"), data, 0o600)
}

// Apply enables services in Enabled and disables services in Disabled via systemctl.
func (s *ServiceEnsure) Apply(ctx context.Context) error {
	for _, svc := range s.Enabled {
		if out, err := exec.CommandContext(ctx, "systemctl", "enable", "--now", svc).CombinedOutput(); err != nil { //nolint:gosec
			return fmt.Errorf("service_ensure enable %s: %s: %w", svc, string(out), err)
		}
	}
	for _, svc := range s.Disabled {
		if out, err := exec.CommandContext(ctx, "systemctl", "disable", "--now", svc).CombinedOutput(); err != nil { //nolint:gosec
			if !strings.Contains(string(out), "not-found") {
				return fmt.Errorf("service_ensure disable %s: %s: %w", svc, string(out), err)
			}
		}
	}
	return nil
}

// Verify checks that Enabled services are active and Disabled services are not.
func (s *ServiceEnsure) Verify(ctx context.Context) (bool, string, error) {
	for _, svc := range s.Enabled {
		out, err := exec.CommandContext(ctx, "systemctl", "is-active", svc).Output() //nolint:gosec
		if err != nil || strings.TrimSpace(string(out)) != "active" {
			return false, fmt.Sprintf("service %s not active", svc), nil
		}
	}
	for _, svc := range s.Disabled {
		out, _ := exec.CommandContext(ctx, "systemctl", "is-active", svc).Output() //nolint:gosec
		if strings.TrimSpace(string(out)) == "active" {
			return false, fmt.Sprintf("service %s should be inactive", svc), nil
		}
	}
	return true, "", nil
}
