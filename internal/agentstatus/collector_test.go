package agentstatus

import (
	"runtime"
	"testing"
)

func TestCollectReturnsPlausibleSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("collector reads /proc; Linux only")
	}
	s, err := Collect()
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if s.UptimeSeconds == 0 {
		t.Error("UptimeSeconds should be > 0")
	}
	if s.RAMTotalMB == 0 {
		t.Error("RAMTotalMB should be > 0")
	}
	if s.DiskTotalGB == 0 {
		t.Error("DiskTotalGB should be > 0")
	}
	if s.RAMUsedMB > s.RAMTotalMB {
		t.Errorf("RAMUsedMB %d > RAMTotalMB %d", s.RAMUsedMB, s.RAMTotalMB)
	}
	if s.DiskUsedPct > 100 {
		t.Errorf("DiskUsedPct = %d, want 0..100", s.DiskUsedPct)
	}
}

func TestToHeartbeatPopulatesFields(t *testing.T) {
	s := &Snapshot{
		UptimeSeconds: 1234,
		LoadAvg1m:     0.5,
		LoadAvg5m:     0.7,
		LoadAvg15m:    0.9,
		RAMUsedMB:     100,
		RAMTotalMB:    1000,
		DiskUsedGB:    20,
		DiskTotalGB:   100,
		DiskUsedPct:   20,
	}
	hb := ToHeartbeat(s, "device-xyz", "0.1.0-test")
	if hb.GetDeviceId().GetId() != "device-xyz" {
		t.Errorf("device_id = %q", hb.GetDeviceId().GetId())
	}
	if hb.GetUptimeSeconds() != 1234 {
		t.Errorf("uptime = %d", hb.GetUptimeSeconds())
	}
	if hb.GetAgentVersion() != "0.1.0-test" {
		t.Errorf("agent_version = %q", hb.GetAgentVersion())
	}
	if hb.GetTimestamp() == nil {
		t.Error("timestamp must be set")
	}
}
