// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"testing"
)

func TestCollectBattery_EnergyUnits_Healthy(t *testing.T) {
	got, err := collectBattery("testdata/sysfs/power_supply")
	if err != nil {
		t.Fatalf("collectBattery: unexpected error: %v", err)
	}
	if !got.Present {
		t.Fatalf("Present: want true, got false")
	}
	if got.HealthPct != 84 {
		t.Errorf("HealthPct: want 84, got %d", got.HealthPct)
	}
	if got.CycleCount != 312 {
		t.Errorf("CycleCount: want 312, got %d", got.CycleCount)
	}
	if got.Status != "Charging" {
		t.Errorf("Status: want %q, got %q", "Charging", got.Status)
	}
	if got.ChargePct != 67 {
		t.Errorf("ChargePct: want 67, got %d", got.ChargePct)
	}
	if got.DesignCapacityMwh != 50000 {
		t.Errorf("DesignCapacityMwh: want 50000, got %d", got.DesignCapacityMwh)
	}
	if got.FullCapacityMwh != 42000 {
		t.Errorf("FullCapacityMwh: want 42000, got %d", got.FullCapacityMwh)
	}
}

func TestCollectBattery_ChargeUnits_FallsBack(t *testing.T) {
	got, err := collectBattery("testdata/sysfs/power_supply-charge-units")
	if err != nil {
		t.Fatalf("collectBattery: unexpected error: %v", err)
	}
	if !got.Present {
		t.Fatalf("Present: want true, got false")
	}
	if got.HealthPct != 80 {
		t.Errorf("HealthPct: want 80 (charge_* fallback), got %d", got.HealthPct)
	}
}

func TestCollectBattery_NoBattery_ReturnsAbsent(t *testing.T) {
	got, err := collectBattery("testdata/sysfs/power_supply-empty")
	if err != nil {
		t.Fatalf("collectBattery: unexpected error: %v", err)
	}
	if got.Present {
		t.Errorf("Present: want false (empty tree), got true")
	}
}
