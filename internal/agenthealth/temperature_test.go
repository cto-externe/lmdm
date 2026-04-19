// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"strings"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func TestCollectTemperatures_PicksCpuAndGpu_SkipsNvme(t *testing.T) {
	tr := collectTemperatures("testdata/sysfs/hwmon")
	if tr == nil {
		t.Fatalf("collectTemperatures returned nil")
	}

	// CPU: coretemp/hwmon0 has Package id 0 @ 45°C and Core 0 @ 46°C, both crit 100°C.
	if got, want := len(tr.Cpu), 2; got != want {
		t.Fatalf("CPU sensor count: want %d, got %d (%+v)", want, got, tr.Cpu)
	}
	cpuByLabel := indexByLabel(tr.Cpu)
	pkg, ok := cpuByLabel["Package id 0"]
	if !ok {
		t.Fatalf("missing CPU sensor %q (got labels %v)", "Package id 0", labels(tr.Cpu))
	}
	if pkg.TemperatureCelsius != 45 {
		t.Errorf("Package id 0 °C: want 45, got %d", pkg.TemperatureCelsius)
	}
	if pkg.CriticalThreshold != 100 {
		t.Errorf("Package id 0 crit: want 100, got %d", pkg.CriticalThreshold)
	}
	if pkg.HighThreshold != 0 {
		t.Errorf("Package id 0 high: want 0 (no temp1_max in fixture), got %d", pkg.HighThreshold)
	}
	core, ok := cpuByLabel["Core 0"]
	if !ok {
		t.Fatalf("missing CPU sensor %q (got labels %v)", "Core 0", labels(tr.Cpu))
	}
	if core.TemperatureCelsius != 46 {
		t.Errorf("Core 0 °C: want 46, got %d", core.TemperatureCelsius)
	}
	if core.CriticalThreshold != 100 {
		t.Errorf("Core 0 crit: want 100, got %d", core.CriticalThreshold)
	}

	// GPU: amdgpu/hwmon2 has edge @ 55°C.
	if got, want := len(tr.Gpu), 1; got != want {
		t.Fatalf("GPU sensor count: want %d, got %d (%+v)", want, got, tr.Gpu)
	}
	if tr.Gpu[0].Label != "edge" {
		t.Errorf("GPU label: want %q, got %q", "edge", tr.Gpu[0].Label)
	}
	if tr.Gpu[0].TemperatureCelsius != 55 {
		t.Errorf("GPU °C: want 55, got %d", tr.Gpu[0].TemperatureCelsius)
	}

	// Other: hwmon3-empty has acpitz name but no temp inputs, so it produces nothing.
	if len(tr.Other) != 0 {
		t.Errorf("Other sensors: want 0, got %d (%+v)", len(tr.Other), tr.Other)
	}

	// NVMe must not leak into any bucket.
	for _, s := range append(append([]*lmdmv1.TemperatureSensor{}, tr.Cpu...), append(tr.Gpu, tr.Other...)...) {
		// nvme fixture's only temp would synthesize label "nvme_temp1" (no label file).
		if strings.Contains(strings.ToLower(s.Label), "nvme") {
			t.Errorf("NVMe sensor leaked into readings: %+v", s)
		}
		// And the NVMe temperature value (38°C) must not appear under that synthesized name.
		if s.TemperatureCelsius == 38 && strings.HasPrefix(s.Label, "nvme") {
			t.Errorf("NVMe temperature value leaked: %+v", s)
		}
	}
}

func TestCollectTemperatures_MissingDir_ReturnsEmptyReadings(t *testing.T) {
	tr := collectTemperatures("testdata/sysfs/does-not-exist")
	if tr == nil {
		t.Fatalf("collectTemperatures returned nil for missing dir; want non-nil empty readings")
	}
	if len(tr.Cpu) != 0 || len(tr.Gpu) != 0 || len(tr.Other) != 0 {
		t.Errorf("missing dir should yield empty readings, got %+v", tr)
	}
}

func TestCollectTemperatures_HwmonWithoutTempFiles_Ignored(t *testing.T) {
	tr := collectTemperatures("testdata/sysfs/hwmon-no-temps")
	if tr == nil {
		t.Fatalf("collectTemperatures returned nil")
	}
	if len(tr.Cpu) != 0 || len(tr.Gpu) != 0 || len(tr.Other) != 0 {
		t.Errorf("hwmon entry without temp*_input must yield no sensors, got %+v", tr)
	}
}

func indexByLabel(ss []*lmdmv1.TemperatureSensor) map[string]*lmdmv1.TemperatureSensor {
	m := make(map[string]*lmdmv1.TemperatureSensor, len(ss))
	for _, s := range ss {
		m[s.Label] = s
	}
	return m
}

func labels(ss []*lmdmv1.TemperatureSensor) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.Label)
	}
	return out
}
