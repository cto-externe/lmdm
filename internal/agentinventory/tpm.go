// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"os"
	"path/filepath"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// tpmRoot is the kernel-exposed directory for TPM devices. tpm0 is the first
// (and usually only) instance.
const tpmRoot = "/sys/class/tpm"

// collectTPMFrom returns TPMInfo when a tpm0 subdirectory exists under
// `root`, or nil when no TPM is detected. Returning nil is deliberate: proto
// message-typed fields treat nil as "not set", so a host without a TPM
// simply omits the field from the report instead of surfacing a misleading
// Present=false struct.
//
// Ownership status is not exposed via sysfs; Owned stays false at MVP.
func collectTPMFrom(root string) *lmdmv1.TPMInfo {
	tpmDir := filepath.Join(root, "tpm0")
	if _, err := os.Stat(tpmDir); err != nil {
		return nil
	}
	major := readTrim(filepath.Join(tpmDir, "tpm_version_major"))
	minor := readTrim(filepath.Join(tpmDir, "tpm_version_minor"))
	version := ""
	if major != "" {
		version = major
		if minor != "" {
			version += "." + minor
		}
	}
	return &lmdmv1.TPMInfo{Present: true, Version: version}
}

func readTrim(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // path is constructed from a fixed /sys subtree
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
