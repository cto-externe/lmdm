// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// modprobeDir is the directory where modprobe drop-in files are written.
// Overridable in tests.
var modprobeDir = "/etc/modprobe.d"

// procModulesPath is the path to /proc/modules, overridable in tests.
var procModulesPath = "/proc/modules"

var (
	reSafeName       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reSafeModuleName = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
)

func isSafeName(s string) bool {
	return reSafeName.MatchString(s)
}

func isSafeModuleName(s string) bool {
	return reSafeModuleName.MatchString(s)
}

// KernelModuleBlacklist writes a modprobe drop-in that prevents listed kernel
// modules from loading by redirecting their install command to /bin/true.
type KernelModuleBlacklist struct {
	Name    string
	Modules []string
}

// NewKernelModuleBlacklist constructs a KernelModuleBlacklist from the YAML
// params map. Validates name and modules and sorts modules for deterministic output.
func NewKernelModuleBlacklist(params map[string]any) (Action, error) {
	name, _ := params["name"].(string)
	if name == "" {
		return nil, errors.New("kernel_module_blacklist: name is required")
	}
	if !isSafeName(name) {
		return nil, fmt.Errorf("kernel_module_blacklist: unsafe name %q (must match [A-Za-z0-9_-]{1,64})", name)
	}

	rawModules, ok := params["modules"]
	if !ok {
		return nil, errors.New("kernel_module_blacklist: modules is required")
	}
	moduleSlice, ok := rawModules.([]any)
	if !ok {
		return nil, errors.New("kernel_module_blacklist: modules must be a list")
	}
	if len(moduleSlice) == 0 {
		return nil, errors.New("kernel_module_blacklist: modules must be non-empty")
	}

	modules := make([]string, 0, len(moduleSlice))
	for _, m := range moduleSlice {
		ms, ok := m.(string)
		if !ok {
			return nil, fmt.Errorf("kernel_module_blacklist: module name must be a string, got %T", m)
		}
		if !isSafeModuleName(ms) {
			return nil, fmt.Errorf("kernel_module_blacklist: unsafe module name %q (must match [A-Za-z0-9_]{1,64}, no dashes)", ms)
		}
		modules = append(modules, ms)
	}
	sort.Strings(modules)

	return &KernelModuleBlacklist{Name: name, Modules: modules}, nil
}

// confPath returns the target path for the modprobe drop-in file.
func (k *KernelModuleBlacklist) confPath() string {
	return filepath.Join(modprobeDir, "lmdm-"+k.Name+".conf")
}

// render produces the modprobe drop-in file content.
func (k *KernelModuleBlacklist) render() []byte {
	var sb strings.Builder
	sb.WriteString("# Managed by LMDM — kernel_module_blacklist/")
	sb.WriteString(k.Name)
	sb.WriteString("\n")
	sb.WriteString("# Do not edit by hand; changes will be overwritten on next profile apply.\n")
	for _, m := range k.Modules {
		sb.WriteString("install ")
		sb.WriteString(m)
		sb.WriteString(" /bin/true\n")
	}
	return []byte(sb.String())
}

// Validate checks that Name and Modules are still well-formed.
func (k *KernelModuleBlacklist) Validate() error {
	if !isSafeName(k.Name) {
		return fmt.Errorf("kernel_module_blacklist: unsafe name %q", k.Name)
	}
	if len(k.Modules) == 0 {
		return errors.New("kernel_module_blacklist: modules must be non-empty")
	}
	for _, m := range k.Modules {
		if !isSafeModuleName(m) {
			return fmt.Errorf("kernel_module_blacklist: unsafe module name %q", m)
		}
	}
	return nil
}

// Snapshot saves the current on-disk state of the modprobe conf file.
// If the file exists it is copied under snapDir/files/etc/modprobe.d/lmdm-{name}.conf.
// If absent, nothing is written — this matches the FileContent.Snapshot convention.
// A consequence is that a file created by Apply will remain after rollback; a future
// RollbackProvider implementation can address precise undo semantics.
func (k *KernelModuleBlacklist) Snapshot(_ context.Context, snapDir string) error {
	src := k.confPath()
	data, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil // file didn't exist before Apply — nothing to back up
		}
		return fmt.Errorf("kernel_module_blacklist snapshot read %s: %w", src, err)
	}
	// Canonical relative path for the snapshot artifact — always under etc/modprobe.d.
	canonicalRel := filepath.Join("etc", "modprobe.d", "lmdm-"+k.Name+".conf")
	dest := filepath.Join(snapDir, "files", canonicalRel)
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return fmt.Errorf("kernel_module_blacklist snapshot mkdir: %w", err)
	}
	return os.WriteFile(dest, data, 0o644) //nolint:gosec // snapshot of a world-readable config file
}

// Apply writes the modprobe drop-in file, creating the directory if needed.
func (k *KernelModuleBlacklist) Apply(_ context.Context) error {
	if err := os.MkdirAll(modprobeDir, 0o755); err != nil { //nolint:gosec
		return fmt.Errorf("kernel_module_blacklist mkdir %s: %w", modprobeDir, err)
	}
	return os.WriteFile(k.confPath(), k.render(), 0o644) //nolint:gosec
}

// Verify checks whether the modprobe drop-in file matches the desired content.
// It also logs a warning for any blacklisted modules that are currently loaded,
// but this does NOT cause Verify to return false.
func (k *KernelModuleBlacklist) Verify(ctx context.Context) (bool, string, error) {
	data, err := os.ReadFile(k.confPath()) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return false, "file missing", nil
		}
		return false, "", fmt.Errorf("kernel_module_blacklist verify read: %w", err)
	}

	if string(data) != string(k.render()) {
		return false, "file content drift", nil
	}

	// Informational warning: log any blacklisted modules that are currently loaded.
	if loaded := k.loadedBlacklisted(); len(loaded) > 0 {
		slog.WarnContext(ctx, "kernel_module_blacklist: blacklisted modules currently loaded",
			"action_name", k.Name,
			"loaded_modules", loaded,
		)
	}

	return true, "", nil
}

// loadedBlacklisted returns the subset of k.Modules that are currently loaded
// according to procModulesPath. Errors are silently ignored (best-effort).
func (k *KernelModuleBlacklist) loadedBlacklisted() []string {
	f, err := os.Open(procModulesPath) //nolint:gosec
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck // best-effort read; ignoring close error is acceptable

	// Build a set for O(1) lookup.
	want := make(map[string]struct{}, len(k.Modules))
	for _, m := range k.Modules {
		want[m] = struct{}{}
	}

	var loaded []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Each line starts with the module name followed by a space.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		mod := fields[0]
		if _, ok := want[mod]; ok {
			loaded = append(loaded, mod)
		}
	}
	return loaded
}
