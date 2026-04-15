// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// parseMemInfo extracts MemTotal from /proc/meminfo-style content. DIMM
// modules are out of scope for MVP — the Modules field is left as an empty
// slice. (Retrieving DIMM info requires dmidecode and root.)
func parseMemInfo(r io.Reader) *lmdmv1.MemoryInfo {
	info := &lmdmv1.MemoryInfo{Modules: []*lmdmv1.MemoryModule{}}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		info.TotalMb = kb / 1024
		break
	}
	return info
}
