// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"testing"
)

const anssiMinimalYAML = `kind: profile
metadata:
  name: anssi-minimal
  version: "1.0"
  description: "Durcissement ANSSI niveau minimal (chrony + sysctl)"
  locked: false

policies:
  - name: ntp-chrony
    actions:
      - type: package_ensure
        params:
          present:
            - chrony
          absent:
            - ntp
            - ntpdate
      - type: service_ensure
        params:
          enabled:
            - chronyd
          disabled:
            - systemd-timesyncd
            - ntpd
      - type: file_content
        params:
          path: /etc/chrony/chrony.conf
          content: |
            server 0.fr.pool.ntp.org iburst
            server 1.fr.pool.ntp.org iburst
            driftfile /var/lib/chrony/chrony.drift
            makestep 1.0 3
            rtcsync

  - name: sysctl-hardening
    actions:
      - type: sysctl
        params:
          net.ipv4.ip_forward: "0"
          net.ipv4.conf.all.rp_filter: "1"
          net.ipv4.conf.all.accept_redirects: "0"
          kernel.sysrq: "0"
`

func TestParseProfileYAML(t *testing.T) {
	reg := DefaultRegistry()
	def, actions, err := ParseProfile([]byte(anssiMinimalYAML), reg)
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	if def.Name != "anssi-minimal" || def.Version != "1.0" {
		t.Errorf("metadata: %+v", def)
	}
	if def.Description != "Durcissement ANSSI niveau minimal (chrony + sysctl)" {
		t.Errorf("description: %q", def.Description)
	}
	if len(def.Policies) != 2 {
		t.Fatalf("len(Policies) = %d, want 2", len(def.Policies))
	}
	if def.Policies[0].Name != "ntp-chrony" {
		t.Errorf("policy[0].Name = %q", def.Policies[0].Name)
	}

	// 3 actions from ntp-chrony + 1 from sysctl-hardening = 4 total.
	if len(actions) != 4 {
		t.Fatalf("len(actions) = %d, want 4", len(actions))
	}
	types := map[string]int{}
	for _, a := range actions {
		types[a.Type]++
	}
	if types["package_ensure"] != 1 || types["service_ensure"] != 1 ||
		types["file_content"] != 1 || types["sysctl"] != 1 {
		t.Errorf("types = %+v", types)
	}
}

func TestParseProfileInvalidYAML(t *testing.T) {
	_, _, err := ParseProfile([]byte("not: valid: yaml: {{{"), DefaultRegistry())
	if err == nil {
		t.Fatal("must reject invalid YAML")
	}
}

func TestParseProfileUnknownActionType(t *testing.T) {
	yaml := `kind: profile
metadata:
  name: test
policies:
  - name: p
    actions:
      - type: unknown_action
        params: {}
`
	_, _, err := ParseProfile([]byte(yaml), DefaultRegistry())
	if err == nil {
		t.Fatal("must reject unknown action type")
	}
}
