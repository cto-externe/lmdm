// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// collectTemperatures scans /sys/class/hwmon (or a fixture root) and returns
// categorized temperature sensors. NVMe hwmon entries are skipped because
// disk temperatures are reported by the NVMe SMART log collector.
//
// The returned value is never nil; on a missing root or empty tree, it
// returns a TemperatureReadings with empty slices.
func collectTemperatures(hwmonRoot string) *lmdmv1.TemperatureReadings {
	tr := &lmdmv1.TemperatureReadings{}
	entries, err := os.ReadDir(hwmonRoot)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("agenthealth: read hwmon root", "path", hwmonRoot, "err", err)
		}
		return tr
	}
	for _, e := range entries {
		dir := filepath.Join(hwmonRoot, e.Name())
		name := strings.TrimSpace(readStringFile(dir, "name"))
		if name == "" {
			continue
		}
		if name == "nvme" {
			// NVMe disk temperatures are reported via the NVMe SMART log.
			continue
		}
		sensors := readHwmonSensors(dir, name)
		if len(sensors) == 0 {
			continue
		}
		switch name {
		case "coretemp", "k10temp", "zenpower", "cpu_thermal":
			tr.Cpu = append(tr.Cpu, sensors...)
		case "amdgpu", "nouveau", "radeon", "nvidia":
			tr.Gpu = append(tr.Gpu, sensors...)
		default:
			tr.Other = append(tr.Other, sensors...)
		}
	}
	return tr
}

// readHwmonSensors enumerates temp*_input files in the given hwmon directory
// and returns one TemperatureSensor per sensor. Sensors that fail to read
// are skipped with a WARN log and do not abort the whole directory.
func readHwmonSensors(dir, hwmonName string) []*lmdmv1.TemperatureSensor {
	matches, err := filepath.Glob(filepath.Join(dir, "temp*_input"))
	if err != nil {
		slog.Warn("agenthealth: glob hwmon temp inputs", "path", dir, "err", err)
		return nil
	}
	if len(matches) == 0 {
		return nil
	}
	// Stable order across runs (filepath.Glob returns lexically sorted, but
	// be explicit so we are not at the mercy of platform changes).
	sort.Strings(matches)

	out := make([]*lmdmv1.TemperatureSensor, 0, len(matches))
	for _, inputPath := range matches {
		base := filepath.Base(inputPath) // e.g. "temp1_input"
		idx := strings.TrimSuffix(strings.TrimPrefix(base, "temp"), "_input")
		if idx == "" {
			continue
		}

		raw := strings.TrimSpace(readStringFile(dir, base))
		if raw == "" {
			slog.Warn("agenthealth: empty hwmon temp input", "path", inputPath)
			continue
		}
		milli, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			slog.Warn("agenthealth: parse hwmon temp input", "path", inputPath, "err", err)
			continue
		}

		label := strings.TrimSpace(readStringFile(dir, fmt.Sprintf("temp%s_label", idx)))
		if label == "" {
			label = fmt.Sprintf("%s_temp%s", hwmonName, idx)
		}

		s := &lmdmv1.TemperatureSensor{
			Label:              label,
			TemperatureCelsius: int32(milli / 1000),
		}
		if v, ok := readMilliCelsius(dir, fmt.Sprintf("temp%s_max", idx)); ok {
			s.HighThreshold = v
		}
		if v, ok := readMilliCelsius(dir, fmt.Sprintf("temp%s_crit", idx)); ok {
			s.CriticalThreshold = v
		}
		out = append(out, s)
	}
	return out
}

// readMilliCelsius reads a millidegree-Celsius sysfs file and returns the
// value in degrees Celsius. The second return is false when the file is
// missing or unparseable; callers should leave the corresponding proto
// field at its zero value in that case.
func readMilliCelsius(dir, name string) (int32, bool) {
	raw := strings.TrimSpace(readStringFile(dir, name))
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		slog.Warn("agenthealth: parse hwmon threshold", "path", filepath.Join(dir, name), "err", err)
		return 0, false
	}
	return int32(v / 1000), true
}
