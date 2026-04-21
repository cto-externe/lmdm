// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileContent writes a file at a given path with literal content.
type FileContent struct {
	Path             string
	Content          string
	PostApplyCommand string
	PostApplyTimeout time.Duration
}

// NewFileContent constructs a FileContent from the YAML params map.
func NewFileContent(params map[string]any) (Action, error) {
	path, _ := params["path"].(string)
	content, _ := params["content"].(string)
	if path == "" {
		return nil, errors.New("file_content: path is required")
	}
	fc := &FileContent{Path: path, Content: content}
	if v, ok := params["post_apply_command"].(string); ok {
		fc.PostApplyCommand = v
	}
	if v, ok := params["post_apply_timeout"].(string); ok {
		if d, err := time.ParseDuration(v); err == nil {
			fc.PostApplyTimeout = d
		}
	}
	return fc, nil
}

// Validate checks that FileContent parameters are well-formed.
func (f *FileContent) Validate() error {
	if f.Path == "" {
		return errors.New("file_content: path is required")
	}
	return nil
}

// Snapshot saves the current file contents (if the file exists) to snapDir.
func (f *FileContent) Snapshot(_ context.Context, snapDir string) error {
	data, err := os.ReadFile(f.Path) //nolint:gosec // path is from a signed profile
	if err != nil {
		if os.IsNotExist(err) {
			return nil // file doesn't exist yet — nothing to back up
		}
		return fmt.Errorf("file_content snapshot %s: %w", f.Path, err)
	}
	backupPath := filepath.Join(snapDir, "files", f.Path)
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(backupPath, data, 0o600) //nolint:gosec // backupPath is constructed from snapDir + cleaned path
}

// Apply writes the desired content to the target path, creating parent dirs as needed.
func (f *FileContent) Apply(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil { //nolint:gosec // path is from a signed profile
		return fmt.Errorf("file_content mkdir %s: %w", f.Path, err)
	}
	if err := os.WriteFile(f.Path, []byte(f.Content), 0o644); err != nil { //nolint:gosec // mode 644 for config files
		return err
	}
	if _, err := runPostApply(ctx, f.PostApplyCommand, f.PostApplyTimeout); err != nil {
		return err
	}
	return nil
}

// Verify checks whether the file at Path matches the desired Content via sha256.
func (f *FileContent) Verify(_ context.Context) (bool, string, error) {
	data, err := os.ReadFile(f.Path) //nolint:gosec // path is from a signed profile
	if err != nil {
		return false, fmt.Sprintf("file %s unreadable: %v", f.Path, err), nil
	}
	expected := sha256.Sum256([]byte(f.Content))
	actual := sha256.Sum256(data)
	if expected != actual {
		return false, fmt.Sprintf("file %s content differs (expected sha256 %s, got %s)",
			f.Path, hex.EncodeToString(expected[:8]), hex.EncodeToString(actual[:8])), nil
	}
	return true, "", nil
}
