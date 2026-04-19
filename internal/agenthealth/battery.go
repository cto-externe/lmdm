// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// collectBattery scans the given sysfs root (`/sys/class/power_supply` in prod,
// a fixture root in tests) and returns the first Battery-typed device.
// If no battery is present, returns {Present: false} and no error.
func collectBattery(psRoot string) (*lmdmv1.BatteryHealth, error) {
	entries, err := os.ReadDir(psRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return &lmdmv1.BatteryHealth{Present: false}, nil
		}
		return nil, err
	}
	for _, e := range entries {
		dir := filepath.Join(psRoot, e.Name())
		typeBytes, _ := os.ReadFile(filepath.Join(dir, "type"))
		if strings.TrimSpace(string(typeBytes)) != "Battery" {
			continue
		}
		return readBatteryDir(dir)
	}
	return &lmdmv1.BatteryHealth{Present: false}, nil
}

func readBatteryDir(dir string) (*lmdmv1.BatteryHealth, error) {
	b := &lmdmv1.BatteryHealth{Present: true}
	// Prefer energy_* (µWh). Fall back to charge_* (µAh) when design/full use charge units.
	designFull := readUintFile(dir, "energy_full_design")
	full := readUintFile(dir, "energy_full")
	if designFull == 0 || full == 0 {
		designFull = readUintFile(dir, "charge_full_design")
		full = readUintFile(dir, "charge_full")
	}
	// Convert µ-unit to mWh / mAh (divide by 1000) for the proto.
	b.DesignCapacityMwh = uint32(designFull / 1000)
	b.FullCapacityMwh = uint32(full / 1000)
	if designFull > 0 && full > 0 {
		b.HealthPct = uint32((full * 100) / designFull)
	}
	b.CycleCount = uint32(readUintFile(dir, "cycle_count"))
	b.Status = strings.TrimSpace(readStringFile(dir, "status"))
	b.ChargePct = uint32(readUintFile(dir, "capacity"))
	return b, nil
}

func readStringFile(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("agenthealth: read sysfs string", "path", filepath.Join(dir, name), "err", err)
		}
		return ""
	}
	return string(b)
}

func readUintFile(dir, name string) uint64 {
	s := strings.TrimSpace(readStringFile(dir, name))
	if s == "" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		slog.Warn("agenthealth: parse sysfs uint", "path", filepath.Join(dir, name), "err", err)
		return 0
	}
	return v
}
