// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"text/template"
	"time"
)

// TemplateVars holds the per-device variables injected into a FileTemplate at
// Apply/Verify time. The agent calls SetVars before each invocation.
type TemplateVars struct {
	Hostname string
	DeviceID string
	TenantID string
	SiteID   string // "" if no site
	GroupIDs []string
}

// FileTemplate writes a file whose content is produced by rendering a Go
// text/template against TemplateVars.
type FileTemplate struct {
	Name             string
	Path             string
	Mode             os.FileMode   // default 0o644
	Owner            string        // optional
	Group            string        // optional
	Content          string        // raw template source
	PostApplyCommand string        // optional hook
	PostApplyTimeout time.Duration // optional; 0 → runPostApply default

	tpl  *template.Template
	vars TemplateVars
}

// NewFileTemplate constructs a FileTemplate from the YAML params map.
// The template is parsed at construction time; a syntax error returns an error
// immediately (fail-fast).
func NewFileTemplate(params map[string]any) (Action, error) {
	name, _ := params["name"].(string)
	path, _ := params["path"].(string)
	content, _ := params["content"].(string)

	if name == "" {
		return nil, errors.New("file_template: name is required")
	}
	if path == "" {
		return nil, errors.New("file_template: path is required")
	}
	if !isAbsPath(path) {
		return nil, fmt.Errorf("file_template: path %q must be absolute", path)
	}
	if content == "" {
		return nil, errors.New("file_template: content is required")
	}

	// Fail-fast template parse. missingkey=zero silences unknown field access so
	// that {{.Unknown}} renders as "<no value>" rather than erroring at execute time.
	tpl, err := template.New(name).Option("missingkey=zero").Parse(content)
	if err != nil {
		return nil, fmt.Errorf("file_template %q: template parse error: %w", name, err)
	}

	f := &FileTemplate{
		Name:    name,
		Path:    path,
		Mode:    0o644,
		Content: content,
		tpl:     tpl,
	}

	// Optional: mode.
	if v, ok := params["mode"].(string); ok && v != "" {
		bits, err := strconv.ParseUint(v, 8, 32)
		if err != nil {
			return nil, fmt.Errorf("file_template: invalid mode %q: %w", v, err)
		}
		f.Mode = os.FileMode(bits)
	}

	// Optional: owner / group.
	if v, ok := params["owner"].(string); ok {
		f.Owner = v
	}
	if v, ok := params["group"].(string); ok {
		f.Group = v
	}

	// Optional: post_apply_command / post_apply_timeout.
	if v, ok := params["post_apply_command"].(string); ok {
		f.PostApplyCommand = v
	}
	if v, ok := params["post_apply_timeout"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("file_template: invalid post_apply_timeout %q: %w", v, err)
		}
		f.PostApplyTimeout = d
	}

	return f, nil
}

// isAbsPath reports whether path starts with "/".
func isAbsPath(path string) bool {
	return len(path) > 0 && path[0] == '/'
}

// SetVars injects the per-device variables used at Apply and Verify time.
func (f *FileTemplate) SetVars(vars TemplateVars) {
	f.vars = vars
}

// Validate re-checks invariants. Constructor already enforces them; this is a
// secondary safety net for callers that re-use the struct.
func (f *FileTemplate) Validate() error {
	if f.Path == "" {
		return errors.New("file_template: path is required")
	}
	if !isAbsPath(f.Path) {
		return fmt.Errorf("file_template: path %q must be absolute", f.Path)
	}
	if f.Name == "" {
		return errors.New("file_template: name is required")
	}
	return nil
}

// Snapshot saves the current file (if it exists) to {snapDir}/files/{path}.
func (f *FileTemplate) Snapshot(_ context.Context, snapDir string) error {
	data, err := os.ReadFile(f.Path) //nolint:gosec // path from signed profile
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("file_template snapshot %s: %w", f.Path, err)
	}
	backupPath := filepath.Join(snapDir, "files", f.Path)
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(backupPath, data, 0o600) //nolint:gosec
}

// varsMap converts TemplateVars to a map[string]any so that missingkey=zero
// applies to unknown field accesses (struct fields not in the map produce
// "<no value>" rather than an execute-time error).
func (f *FileTemplate) varsMap() map[string]any {
	return map[string]any{
		"Hostname": f.vars.Hostname,
		"DeviceID": f.vars.DeviceID,
		"TenantID": f.vars.TenantID,
		"SiteID":   f.vars.SiteID,
		"GroupIDs": f.vars.GroupIDs,
	}
}

// render executes the template against the current vars and returns the output.
func (f *FileTemplate) render() ([]byte, error) {
	var buf bytes.Buffer
	if err := f.tpl.Execute(&buf, f.varsMap()); err != nil {
		return nil, fmt.Errorf("file_template %q: render error: %w", f.Name, err)
	}
	return buf.Bytes(), nil
}

// Apply renders the template and writes the result atomically, then runs the
// optional post-apply hook.
func (f *FileTemplate) Apply(ctx context.Context) error {
	rendered, err := f.render()
	if err != nil {
		return err
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil { //nolint:gosec
		return fmt.Errorf("file_template mkdir %s: %w", f.Path, err)
	}

	// Atomic write via tmp + rename.
	tmp := f.Path + ".tmp"
	if err := os.WriteFile(tmp, rendered, f.Mode); err != nil { //nolint:gosec
		return fmt.Errorf("file_template write tmp %s: %w", tmp, err)
	}

	// Optional chown: resolve uid/gid and chown the tempfile BEFORE rename so
	// that a lookup or chown failure leaves no artifact at the target path.
	if f.Owner != "" || f.Group != "" {
		uid, gid := -1, -1
		if f.Owner != "" {
			u, err := user.Lookup(f.Owner)
			if err != nil {
				_ = os.Remove(tmp)
				return fmt.Errorf("file_template: owner lookup %q: %w", f.Owner, err)
			}
			n, _ := strconv.Atoi(u.Uid)
			uid = n
		}
		if f.Group != "" {
			g, err := user.LookupGroup(f.Group)
			if err != nil {
				_ = os.Remove(tmp)
				return fmt.Errorf("file_template: group lookup %q: %w", f.Group, err)
			}
			n, _ := strconv.Atoi(g.Gid)
			gid = n
		}
		if err := os.Chown(tmp, uid, gid); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("file_template chown %s: %w", tmp, err)
		}
	}

	if err := os.Rename(tmp, f.Path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("file_template rename %s: %w", f.Path, err)
	}

	// Optional post-apply hook.
	if _, err := runPostApply(ctx, f.PostApplyCommand, f.PostApplyTimeout); err != nil {
		return err
	}
	return nil
}

// Verify renders the template and compares it to the on-disk file.
// It also checks that the file's permission bits match f.Mode.
func (f *FileTemplate) Verify(_ context.Context) (bool, string, error) {
	rendered, err := f.render()
	if err != nil {
		return false, "", err
	}

	data, err := os.ReadFile(f.Path) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return false, fmt.Sprintf("file_template %s: missing", f.Path), nil
		}
		return false, "", fmt.Errorf("file_template verify read %s: %w", f.Path, err)
	}

	// Content check via sha256.
	want := sha256.Sum256(rendered)
	got := sha256.Sum256(data)
	if want != got {
		return false, fmt.Sprintf("file_template %s: content differs", f.Path), nil
	}

	// Mode check.
	info, err := os.Stat(f.Path)
	if err != nil {
		return false, "", fmt.Errorf("file_template verify stat %s: %w", f.Path, err)
	}
	if info.Mode().Perm() != f.Mode {
		return false, fmt.Sprintf("file_template %s: mode %04o, want %04o",
			f.Path, info.Mode().Perm(), f.Mode), nil
	}

	return true, "", nil
}
