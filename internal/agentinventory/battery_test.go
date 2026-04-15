// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectBatteryAbsentReturnsNil(t *testing.T) {
	dir := t.TempDir() // empty: no BAT* subdir — desktop host
	bat := collectBatteryFrom(dir)
	if bat != nil {
		t.Errorf("Battery should be nil on a desktop (no BAT* subdir), got %+v", bat)
	}
}

func TestCollectBatterySkipsNonBatterySupplies(t *testing.T) {
	// /sys/class/power_supply typically contains AC, BAT0, and sometimes USB
	// power supplies. Only `type == Battery` entries should be considered.
	dir := t.TempDir()
	acDir := filepath.Join(dir, "AC")
	if err := os.MkdirAll(acDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(acDir, "type"), []byte("Mains\n"), 0o644)

	bat := collectBatteryFrom(dir)
	if bat != nil {
		t.Errorf("Battery should be nil when only AC supply is present, got %+v", bat)
	}
}

func TestCollectBatteryPresent(t *testing.T) {
	dir := t.TempDir()
	batDir := filepath.Join(dir, "BAT0")
	if err := os.MkdirAll(batDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// All values in µWh for energy, integer for cycles, text for status.
	writes := map[string]string{
		"type":               "Battery\n",
		"energy_full_design": "57000000\n",
		"energy_full":        "50000000\n",
		"cycle_count":        "312\n",
		"status":             "Discharging\n",
		"capacity":           "78\n",
	}
	for name, v := range writes {
		_ = os.WriteFile(filepath.Join(batDir, name), []byte(v), 0o644)
	}
	bat := collectBatteryFrom(dir)
	if bat == nil {
		t.Fatal("Battery should be non-nil when BAT0 exists")
	}
	if !bat.Present {
		t.Error("Present should be true on a real battery")
	}
	if bat.DesignCapacityMwh != 57000 {
		t.Errorf("DesignCapacityMwh = %d, want 57000", bat.DesignCapacityMwh)
	}
	if bat.FullCapacityMwh != 50000 {
		t.Errorf("FullCapacityMwh = %d, want 50000", bat.FullCapacityMwh)
	}
	if bat.HealthPct != 87 { // 50000/57000 * 100 = 87.7 → truncated to 87
		t.Errorf("HealthPct = %d, want 87", bat.HealthPct)
	}
	if bat.CycleCount != 312 {
		t.Errorf("CycleCount = %d", bat.CycleCount)
	}
	if bat.Status != "discharging" {
		t.Errorf("Status = %q", bat.Status)
	}
	if bat.ChargePct != 78 {
		t.Errorf("ChargePct = %d", bat.ChargePct)
	}
}
