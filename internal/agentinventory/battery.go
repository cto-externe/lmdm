// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// batteryRoot is the kernel-exposed directory listing power supplies.
const batteryRoot = "/sys/class/power_supply"

// collectBatteryFrom scans `root` for a subdirectory whose `type` file reads
// "Battery" and returns its BatteryInfo. Returns nil when no battery is
// found (desktop hosts, servers, VMs): the proto Battery field is optional
// and a nil value omits it from the report cleanly.
//
// Capacity values are reported in mWh (divided by 1000 from the kernel's
// µWh units).
func collectBatteryFrom(root string) *lmdmv1.BatteryInfo {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if strings.ToLower(readTrim(filepath.Join(dir, "type"))) != "battery" {
			continue
		}
		design := readUint(filepath.Join(dir, "energy_full_design")) / 1000
		full := readUint(filepath.Join(dir, "energy_full")) / 1000
		cycles := readUint(filepath.Join(dir, "cycle_count"))
		charge := readUint(filepath.Join(dir, "capacity"))
		status := strings.ToLower(readTrim(filepath.Join(dir, "status")))
		var healthPct uint32
		if design > 0 && full > 0 {
			healthPct = uint32((full * 100) / design)
		}
		return &lmdmv1.BatteryInfo{
			Present:           true,
			DesignCapacityMwh: uint32(design),
			FullCapacityMwh:   uint32(full),
			HealthPct:         healthPct,
			CycleCount:        uint32(cycles),
			Status:            status,
			ChargePct:         uint32(charge),
		}
	}
	return nil
}

func readUint(path string) uint64 {
	s := readTrim(path)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
