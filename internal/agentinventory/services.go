// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"bufio"
	"io"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// parseSystemctlList parses the output of
// `systemctl list-units --type=service --all --no-pager --plain --no-legend`.
// Format (whitespace-separated): UNIT LOAD ACTIVE SUB DESCRIPTION
// Entries whose UNIT does not end with ".service" are skipped.
// The `Enabled` field is NOT populated here — that requires a separate
// `systemctl is-enabled` call per unit. Left false at MVP; enrich later.
func parseSystemctlList(r io.Reader) []*lmdmv1.SystemdService {
	out := []*lmdmv1.SystemdService{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Minimum 4 fields required (UNIT LOAD ACTIVE SUB). Description may
		// be empty or multi-word.
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		unit := fields[0]
		if !strings.HasSuffix(unit, ".service") {
			continue
		}
		load, active, sub := fields[1], fields[2], fields[3]
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		out = append(out, &lmdmv1.SystemdService{
			Name:        unit,
			LoadState:   load,
			ActiveState: active,
			SubState:    sub,
			Description: desc,
		})
	}
	return out
}
