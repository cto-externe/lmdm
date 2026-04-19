// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"context"
	"testing"
)

func TestCollectFirmware_ServiceInactive_ReturnsNil(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"systemctl is-active fwupd.service": []byte("inactive\n"),
		},
		exitCodes: map[string]int{
			"systemctl is-active fwupd.service": 3,
		},
	}
	updates, err := collectFirmware(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Errorf("expected nil updates when fwupd inactive, got %d entries", len(updates))
	}
}

func TestCollectFirmware_ServiceActive_TwoUpdates_Parses(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"systemctl is-active fwupd.service": []byte("active\n"),
			"fwupdmgr get-updates --json":       loadFixture(t, "fwupdmgr-updates.json"),
		},
	}
	updates, err := collectFirmware(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(updates) != 2 {
		t.Fatalf("expected 2 updates, got %d", len(updates))
	}

	sys := updates[0]
	if sys.DeviceName != "System Firmware" {
		t.Errorf("DeviceName: got %q want %q", sys.DeviceName, "System Firmware")
	}
	if sys.DeviceId != "abc123" {
		t.Errorf("DeviceId: got %q want %q", sys.DeviceId, "abc123")
	}
	if sys.CurrentVersion != "1.0.0" {
		t.Errorf("CurrentVersion: got %q want %q", sys.CurrentVersion, "1.0.0")
	}
	if sys.AvailableVersion != "1.0.1" {
		t.Errorf("AvailableVersion: got %q want %q", sys.AvailableVersion, "1.0.1")
	}
	if sys.Vendor != "Lenovo" {
		t.Errorf("Vendor: got %q want %q", sys.Vendor, "Lenovo")
	}
	if sys.Severity != "critical" {
		t.Errorf("Severity: got %q want %q", sys.Severity, "critical")
	}
	if sys.ReleaseUrl != "https://fwupd.org/lvfs/foo.cab" {
		t.Errorf("ReleaseUrl: got %q", sys.ReleaseUrl)
	}
	if sys.SizeBytes != 1048576 {
		t.Errorf("SizeBytes: got %d want %d", sys.SizeBytes, 1048576)
	}
	if !sys.RequiresReboot {
		t.Error("expected RequiresReboot=true on entry with needs-reboot flag")
	}

	tpm := updates[1]
	if tpm.DeviceName != "TPM" {
		t.Errorf("DeviceName: got %q want %q", tpm.DeviceName, "TPM")
	}
	if tpm.Vendor != "Infineon" {
		t.Errorf("Vendor: got %q want %q", tpm.Vendor, "Infineon")
	}
	if tpm.Severity != "medium" {
		t.Errorf("Severity: got %q want %q", tpm.Severity, "medium")
	}
	if tpm.RequiresReboot {
		t.Error("expected RequiresReboot=false on entry without needs-reboot flag")
	}
}

func TestCollectFirmware_NoUpdates_ReturnsEmpty(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"systemctl is-active fwupd.service": []byte("active\n"),
			"fwupdmgr get-updates --json":       loadFixture(t, "fwupdmgr-none.json"),
		},
	}
	updates, err := collectFirmware(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(updates) != 0 {
		t.Errorf("expected 0 updates, got %d", len(updates))
	}
}

func TestCollectFirmware_FwupdmgrMissing_ReturnsNil(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"systemctl is-active fwupd.service": []byte("active\n"),
			// No fixture for "fwupdmgr get-updates --json" — runner returns os.ErrNotExist.
		},
	}
	updates, err := collectFirmware(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates != nil {
		t.Errorf("expected nil updates when fwupdmgr is missing, got %d entries", len(updates))
	}
}
