// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"runtime"
	"testing"
)

func TestCollectOnThisMachine(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("collector reads /proc /sys; Linux only")
	}
	snap := Collect()
	if snap == nil {
		t.Fatal("Collect must never return nil")
	}
	// Hardware: best-effort; CPU model should be non-empty on anything real.
	if snap.Hardware.GetCpu().GetModel() == "" {
		t.Error("cpu.model should be populated from /proc/cpuinfo on Linux")
	}
	if snap.Hardware.GetMemory().GetTotalMb() == 0 {
		t.Error("memory.total_mb should be populated")
	}
	// Software: OS info always present on Linux.
	if snap.Software.GetOs().GetName() == "" {
		t.Error("os.name should be non-empty")
	}
	// Network: hostname always readable.
	if snap.Network.GetHostname() == "" {
		t.Error("network.hostname should be non-empty")
	}
}

func TestToReportWrapsSnapshot(t *testing.T) {
	snap := &Snapshot{}
	rep := ToReport(snap, "device-xyz")
	if rep.GetDeviceId().GetId() != "device-xyz" {
		t.Errorf("device_id = %q", rep.GetDeviceId().GetId())
	}
	if !rep.GetIsFull() {
		t.Error("is_full should be true for MVP reports")
	}
	if rep.GetSchemaVersion() != 1 {
		t.Errorf("schema_version = %d, want 1", rep.GetSchemaVersion())
	}
	if rep.GetTimestamp() == nil {
		t.Error("timestamp must be set")
	}
}
