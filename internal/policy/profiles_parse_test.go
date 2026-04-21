// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"os"
	"testing"
)

func TestParseANSSIProfiles(t *testing.T) {
	profiles := []string{
		"../../profiles/anssi/anssi-minimal.yml",
		"../../profiles/anssi/anssi-intermediaire.yml",
		"../../profiles/anssi/anssi-renforce.yml",
		"../../profiles/anssi/anssi-eleve.yml",
	}
	reg := DefaultRegistry()
	for _, path := range profiles {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path) //nolint:gosec // test-only: reads fixture YAMLs under repo profiles/ dir
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			def, actions, err := ParseProfile(data, reg)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			t.Logf("profile %s: %d policies, %d actions", def.Name, len(def.Policies), len(actions))
		})
	}
}
