// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"context"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// TestCollector_Collect_ProducesScoredSnapshot wires the orchestrator with
// healthy fixtures (one SATA disk + one NVMe disk + the energy-units battery
// fixture + the coretemp/amdgpu hwmon fixture) and an inactive fwupd service.
// Expectation: snapshot is fully populated and OverallScore == GREEN.
func TestCollector_Collect_ProducesScoredSnapshot(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"smartctl -j -a /dev/sda":             loadFixture(t, "smartctl-sata-healthy.json"),
			"nvme smart-log /dev/nvme0n1 -o json": loadFixture(t, "nvme-smart-log-healthy.json"),
			"systemctl is-active fwupd.service":   []byte("inactive\n"),
		},
		exitCodes: map[string]int{
			// systemctl is-active returns 3 when the unit is inactive.
			"systemctl is-active fwupd.service": 3,
		},
	}
	listDisks := func() ([]string, error) {
		return []string{"/dev/sda", "/dev/nvme0n1"}, nil
	}
	c := NewCollectorWithRoots(runner, "testdata/sysfs/power_supply", "testdata/sysfs/hwmon", listDisks)

	snap := c.Collect(context.Background(), "device-abc")
	if snap == nil {
		t.Fatal("Collect returned nil snapshot")
	}
	if snap.Timestamp == nil {
		t.Error("Timestamp: want non-nil")
	}
	if snap.DeviceId == nil || snap.DeviceId.Id != "device-abc" {
		t.Errorf("DeviceId: want id=device-abc, got %+v", snap.DeviceId)
	}
	if got := len(snap.Disks); got != 2 {
		t.Errorf("Disks: want 2, got %d", got)
	}
	if snap.Battery == nil || !snap.Battery.Present {
		t.Errorf("Battery: want present=true, got %+v", snap.Battery)
	}
	if snap.Temperatures == nil || len(snap.Temperatures.Cpu) == 0 {
		t.Errorf("Temperatures.Cpu: want non-empty, got %+v", snap.Temperatures)
	}
	if len(snap.FirmwareUpdates) != 0 {
		t.Errorf("FirmwareUpdates: want empty (fwupd inactive), got %d entries", len(snap.FirmwareUpdates))
	}
	if snap.OverallScore != lmdmv1.HealthScore_HEALTH_SCORE_GREEN {
		t.Errorf("OverallScore: want GREEN, got %v", snap.OverallScore)
	}
}

// TestCollector_Collect_NoDisks_NoBattery_StillProducesSnapshot verifies the
// orchestrator never short-circuits: with zero disks, no battery, no hwmon
// sensors, and no fwupd, the snapshot is still returned and OverallScore
// stays at UNSPECIFIED (no component contributed a non-zero score).
func TestCollector_Collect_NoDisks_NoBattery_StillProducesSnapshot(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"systemctl is-active fwupd.service": []byte("inactive\n"),
		},
		exitCodes: map[string]int{
			"systemctl is-active fwupd.service": 3,
		},
	}
	listDisks := func() ([]string, error) {
		return nil, nil
	}
	c := NewCollectorWithRoots(runner, "testdata/sysfs/power_supply-empty", "testdata/sysfs/hwmon-no-temps", listDisks)

	snap := c.Collect(context.Background(), "device-empty")
	if snap == nil {
		t.Fatal("Collect returned nil snapshot")
	}
	if snap.Timestamp == nil {
		t.Error("Timestamp: want non-nil even on empty host")
	}
	if len(snap.Disks) != 0 {
		t.Errorf("Disks: want 0, got %d", len(snap.Disks))
	}
	if snap.Battery == nil || snap.Battery.Present {
		t.Errorf("Battery: want present=false, got %+v", snap.Battery)
	}
	if snap.Temperatures == nil {
		t.Error("Temperatures: want non-nil empty struct, got nil")
	}
	if snap.OverallScore != lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED {
		t.Errorf("OverallScore: want UNSPECIFIED when no component contributes, got %v", snap.OverallScore)
	}
}
