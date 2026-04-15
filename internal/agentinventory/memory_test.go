// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"strings"
	"testing"
)

const meminfoFixture = `MemTotal:       16328544 kB
MemFree:         3821248 kB
MemAvailable:   10456792 kB
Buffers:          231456 kB
Cached:          5890432 kB
`

func TestParseMemInfoTotal(t *testing.T) {
	mem := parseMemInfo(strings.NewReader(meminfoFixture))
	// 16328544 kB / 1024 = 15945 MB
	if mem.TotalMb != 15945 {
		t.Errorf("TotalMb = %d, want 15945", mem.TotalMb)
	}
	if mem.Modules == nil {
		t.Error("Modules must be non-nil (empty slice is fine)")
	}
}
