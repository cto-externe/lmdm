// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"fmt"
	"os"
	"path/filepath"
)

const snapshotDirMode = 0o700

// CreateSnapshotDir creates and returns the directory
// `<root>/<deploymentID>/` where pre-apply state is backed up.
func CreateSnapshotDir(root, deploymentID string) (string, error) {
	dir := filepath.Join(root, deploymentID)
	if err := os.MkdirAll(dir, snapshotDirMode); err != nil {
		return "", fmt.Errorf("snapshot: mkdir %s: %w", dir, err)
	}
	return dir, nil
}
