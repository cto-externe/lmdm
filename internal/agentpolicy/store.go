// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProfileStore persists applied profiles as individual YAML files on disk.
// Used by the drift detection runner to know which profiles to re-verify.
type ProfileStore struct {
	dir string
}

// NewProfileStore creates a store rooted at dir. The directory is created
// if it doesn't exist on the first Save.
func NewProfileStore(dir string) *ProfileStore {
	return &ProfileStore{dir: dir}
}

// Save writes a profile's YAML to disk as {dir}/{profileID}.yaml.
func (s *ProfileStore) Save(profileID string, yamlContent []byte) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("profile store mkdir: %w", err)
	}
	path := filepath.Join(s.dir, profileID+".yaml")
	return os.WriteFile(path, yamlContent, 0o600)
}

// Remove deletes a profile from the store. No-op if the file doesn't exist.
func (s *ProfileStore) Remove(profileID string) error {
	path := filepath.Join(s.dir, profileID+".yaml")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("profile store remove: %w", err)
	}
	return nil
}

// List returns all stored profiles as a map of profileID → YAML content.
func (s *ProfileStore) List() (map[string][]byte, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]byte{}, nil
		}
		return nil, fmt.Errorf("profile store list: %w", err)
	}
	out := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".yaml")
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name())) //nolint:gosec
		if err != nil {
			continue
		}
		out[id] = data
	}
	return out, nil
}
