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
	"sort"
	"strings"
)

// Sysctl applies kernel parameters via sysctl -w.
type Sysctl struct {
	Values map[string]string
}

// NewSysctl constructs a Sysctl from the YAML params map. All keys are
// treated as sysctl parameter names; values must be strings.
func NewSysctl(params map[string]any) (Action, error) {
	s := &Sysctl{Values: map[string]string{}}
	for k, v := range params {
		sv, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("sysctl: value for %s must be string, got %T", k, v)
		}
		s.Values[k] = sv
	}
	return s, nil
}

// Validate checks that Sysctl parameters are well-formed.
func (s *Sysctl) Validate() error { return nil }

// Snapshot saves the current kernel values for all managed keys to snapDir/sysctl.json.
func (s *Sysctl) Snapshot(ctx context.Context, snapDir string) error {
	current := map[string]string{}
	for k := range s.Values {
		out, err := exec.CommandContext(ctx, "sysctl", "-n", k).Output() //nolint:gosec
		if err == nil {
			current[k] = strings.TrimSpace(string(out))
		}
	}
	data, _ := json.Marshal(current)
	return os.WriteFile(filepath.Join(snapDir, "sysctl.json"), data, 0o600)
}

// Apply sets all kernel parameters via sysctl -w, in sorted key order.
func (s *Sysctl) Apply(ctx context.Context) error {
	keys := make([]string, 0, len(s.Values))
	for k := range s.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		arg := k + "=" + s.Values[k]
		if out, err := exec.CommandContext(ctx, "sysctl", "-w", arg).CombinedOutput(); err != nil { //nolint:gosec
			return fmt.Errorf("sysctl -w %s: %s: %w", arg, string(out), err)
		}
	}
	return nil
}

// Verify checks that every managed kernel parameter matches its desired value.
func (s *Sysctl) Verify(ctx context.Context) (bool, string, error) {
	for k, want := range s.Values {
		out, err := exec.CommandContext(ctx, "sysctl", "-n", k).Output() //nolint:gosec
		if err != nil {
			return false, fmt.Sprintf("sysctl %s: read error: %v", k, err), nil
		}
		got := strings.TrimSpace(string(out))
		if got != want {
			return false, fmt.Sprintf("sysctl %s = %q, want %q", k, got, want), nil
		}
	}
	return true, "", nil
}
