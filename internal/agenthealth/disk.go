// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// Critical SMART attribute IDs per SMART spec and industry consensus.
// Parse by ID (not name): vendors use exotic names and attribute 5 is
// "Reallocated Sector Count" on every SATA/SAS drive regardless of name.
const (
	smartIDReallocatedSectorCt   = 5
	smartIDReportedUncorrectable = 187
	smartIDCommandTimeout        = 188
	smartIDCurrentPendingSector  = 197
	smartIDOfflineUncorrectable  = 198
)

// smartctl exit code bits (documented in smartctl(8) manpage).
// We tolerate non-zero exit codes because smartctl returns informational bits
// along with the JSON payload on stdout.
const (
	smartExitBitCmdLineError   = 1 << 0
	smartExitBitDeviceOpenFail = 1 << 1
	smartExitBitReadFail       = 1 << 2
	smartExitBitFailingNow     = 1 << 3
	smartExitBitFailingPast    = 1 << 4
	smartExitBitThresholdHit   = 1 << 5
	smartExitBitLogged         = 1 << 6
	smartExitBitSelfTestFail   = 1 << 7
)

// listPhysicalDisks scans /sys/block for non-removable, non-virtual block
// devices. Returns device paths like "/dev/sda", "/dev/nvme0n1".
func listPhysicalDisks() ([]string, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, fmt.Errorf("read /sys/block: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		// Skip loop/ram/dm/md/zram virtual devices and optical drives.
		if strings.HasPrefix(name, "loop") ||
			strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "dm-") ||
			strings.HasPrefix(name, "md") ||
			strings.HasPrefix(name, "zram") ||
			strings.HasPrefix(name, "sr") {
			continue
		}
		removable, _ := os.ReadFile(filepath.Join("/sys/block", name, "removable"))
		if strings.TrimSpace(string(removable)) == "1" {
			continue
		}
		out = append(out, "/dev/"+name)
	}
	return out, nil
}

// collectDisks runs smartctl and/or nvme smart-log on every physical disk and
// returns a slice of DiskHealth proto messages. Missing tools log WARN but do
// not fail the collection.
func collectDisks(ctx context.Context, runner CommandRunner) ([]*lmdmv1.DiskHealth, error) {
	return collectDisksFrom(ctx, runner, listPhysicalDisks)
}

// collectDisksFrom is the testable variant that takes an explicit disk lister.
// Production code calls collectDisks; tests inject a stub lister that returns
// canned device paths so the smartctl/nvme command keys line up with fixtures.
func collectDisksFrom(ctx context.Context, runner CommandRunner, listDisks func() ([]string, error)) ([]*lmdmv1.DiskHealth, error) {
	paths, err := listDisks()
	if err != nil {
		return nil, err
	}
	out := make([]*lmdmv1.DiskHealth, 0, len(paths))
	for _, p := range paths {
		name := filepath.Base(p)
		if strings.HasPrefix(name, "nvme") {
			dh, err := collectNVMe(ctx, runner, p)
			if err != nil {
				slog.Warn("agenthealth: nvme collect failed", "device", p, "err", err)
				continue
			}
			out = append(out, dh)
			continue
		}
		dh, err := collectSMART(ctx, runner, p)
		if err != nil {
			slog.Warn("agenthealth: smartctl collect failed", "device", p, "err", err)
			continue
		}
		out = append(out, dh)
	}
	return out, nil
}

// --- smartctl (SATA) ---

type smartctlOutput struct {
	Device struct {
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
	} `json:"device"`
	ModelName   string `json:"model_name"`
	Temperature struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime struct {
		Hours int `json:"hours"`
	} `json:"power_on_time"`
	SmartStatus struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	AtaSmartAttributes struct {
		Table []struct {
			ID     int    `json:"id"`
			Name   string `json:"name"`
			Value  int    `json:"value"`
			Worst  int    `json:"worst"`
			Thresh int    `json:"thresh"`
			Raw    struct {
				Value int64 `json:"value"`
			} `json:"raw"`
			Flags struct {
				String string `json:"string"`
			} `json:"flags"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	AtaSmartSelfTestLog struct {
		Standard struct {
			Table []struct {
				Status struct {
					Passed bool `json:"passed"`
				} `json:"status"`
			} `json:"table"`
		} `json:"standard"`
	} `json:"ata_smart_self_test_log"`
}

func collectSMART(ctx context.Context, runner CommandRunner, device string) (*lmdmv1.DiskHealth, error) {
	stdout, exitCode, err := runner.Run(ctx, "smartctl", "-j", "-a", device)
	if err != nil {
		return nil, fmt.Errorf("smartctl not runnable: %w", err)
	}
	// smartctl uses bitmask exit codes. Accept the output if the JSON parses,
	// regardless of informational bits. Only fatal bits indicate we should not
	// trust the payload.
	failBits := exitCode & (smartExitBitCmdLineError | smartExitBitDeviceOpenFail | smartExitBitReadFail)
	if failBits != 0 {
		return nil, fmt.Errorf("smartctl fatal exit code 0x%x on %s", exitCode, device)
	}
	var raw smartctlOutput
	if err := json.Unmarshal(stdout, &raw); err != nil {
		return nil, fmt.Errorf("smartctl json: %w", err)
	}
	attrs := &lmdmv1.SATASmartAttributes{
		SelfTestPassed: lastSelfTestPassed(&raw),
	}
	for _, a := range raw.AtaSmartAttributes.Table {
		switch a.ID {
		case smartIDReallocatedSectorCt:
			attrs.ReallocatedSectors = uint32(a.Raw.Value)
		case smartIDReportedUncorrectable, smartIDOfflineUncorrectable:
			attrs.UncorrectableErrors += uint32(a.Raw.Value)
		case smartIDCommandTimeout:
			attrs.CommandTimeoutCount = uint32(a.Raw.Value)
		case smartIDCurrentPendingSector:
			attrs.PendingSectors = uint32(a.Raw.Value)
			attrs.CurrentPendingSector = uint32(a.Raw.Value)
		}
		attrs.RawAttributes = append(attrs.RawAttributes, &lmdmv1.SmartAttribute{
			Id:        uint32(a.ID),
			Name:      a.Name,
			Value:     uint32(a.Value),
			Worst:     uint32(a.Worst),
			Threshold: uint32(a.Thresh),
			RawValue:  a.Raw.Value,
			Flags:     a.Flags.String,
		})
	}
	return &lmdmv1.DiskHealth{
		Name:               strings.TrimPrefix(device, "/dev/"),
		Model:              raw.ModelName,
		Type:               "sata",
		SmartPassed:        raw.SmartStatus.Passed,
		TemperatureCelsius: uint32(raw.Temperature.Current),
		PowerOnHours:       uint32(raw.PowerOnTime.Hours),
		SataAttributes:     attrs,
	}, nil
}

func lastSelfTestPassed(raw *smartctlOutput) bool {
	if len(raw.AtaSmartSelfTestLog.Standard.Table) == 0 {
		return true // no self-test yet; don't penalize
	}
	return raw.AtaSmartSelfTestLog.Standard.Table[0].Status.Passed
}

// --- nvme smart-log ---

type nvmeSmartLog struct {
	CriticalWarning   uint32 `json:"critical_warning"`
	Temperature       uint32 `json:"temperature"` // nvme-cli -o json typically reports Celsius already.
	AvailSpare        uint32 `json:"avail_spare"`
	SpareThresh       uint32 `json:"spare_thresh"`
	PercentUsed       uint32 `json:"percent_used"`
	DataUnitsRead     uint64 `json:"data_units_read"`
	DataUnitsWritten  uint64 `json:"data_units_written"`
	HostReadCommands  uint64 `json:"host_read_commands"`
	HostWriteCommands uint64 `json:"host_write_commands"`
	MediaErrors       uint32 `json:"media_errors"`
	NumErrLogEntries  uint32 `json:"num_err_log_entries"`
	UnsafeShutdowns   uint32 `json:"unsafe_shutdowns"`
	PowerCycles       uint32 `json:"power_cycles"`
	PowerOnHours      uint32 `json:"power_on_hours"`
}

func collectNVMe(ctx context.Context, runner CommandRunner, device string) (*lmdmv1.DiskHealth, error) {
	stdout, exitCode, err := runner.Run(ctx, "nvme", "smart-log", device, "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("nvme not runnable: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("nvme smart-log exit %d on %s", exitCode, device)
	}
	var raw nvmeSmartLog
	if err := json.Unmarshal(stdout, &raw); err != nil {
		return nil, fmt.Errorf("nvme smart-log json: %w", err)
	}
	return &lmdmv1.DiskHealth{
		Name:               strings.TrimPrefix(device, "/dev/"),
		Type:               "nvme",
		SmartPassed:        raw.CriticalWarning == 0,
		TemperatureCelsius: raw.Temperature,
		PowerOnHours:       raw.PowerOnHours,
		LifeRemainingPct:   100 - minUint32(raw.PercentUsed, 100),
		NvmeSmartLog: &lmdmv1.NVMeSmartLog{
			CriticalWarning:         raw.CriticalWarning,
			AvailableSparePct:       raw.AvailSpare,
			AvailableSpareThreshold: raw.SpareThresh,
			PercentageUsed:          raw.PercentUsed,
			DataUnitsRead:           raw.DataUnitsRead,
			DataUnitsWritten:        raw.DataUnitsWritten,
			HostReadCommands:        raw.HostReadCommands,
			HostWriteCommands:       raw.HostWriteCommands,
			MediaErrors:             raw.MediaErrors,
			NumErrorLogEntries:      raw.NumErrLogEntries,
			UnsafeShutdowns:         raw.UnsafeShutdowns,
			PowerCycles:             raw.PowerCycles,
		},
	}, nil
}

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
