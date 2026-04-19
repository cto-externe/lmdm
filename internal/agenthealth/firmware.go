// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"context"
	"encoding/json"
	"log/slog"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// collectFirmware probes the fwupd daemon via `systemctl is-active fwupd.service`
// before calling `fwupdmgr get-updates --json`. Returns an empty slice (no error)
// when fwupd is not installed or not running — firmware monitoring is optional
// and absence is not a failure.
func collectFirmware(ctx context.Context, runner CommandRunner) ([]*lmdmv1.FirmwareUpdate, error) {
	_, exit, err := runner.Run(ctx, "systemctl", "is-active", "fwupd.service")
	if err != nil {
		// systemctl missing → not a systemd host. No firmware data.
		slog.Debug("agenthealth: systemctl unavailable, skipping firmware", "err", err)
		return nil, nil
	}
	if exit != 0 {
		slog.Debug("agenthealth: fwupd.service not active, skipping firmware")
		return nil, nil
	}
	stdout, exit, err := runner.Run(ctx, "fwupdmgr", "get-updates", "--json")
	if err != nil {
		slog.Warn("agenthealth: fwupdmgr not runnable, skipping firmware", "err", err)
		return nil, nil
	}
	// fwupdmgr exits non-zero when there are no updates — that's not an error.
	// We parse stdout regardless; if it fails we fall back to empty.
	if len(stdout) == 0 {
		return nil, nil
	}
	var raw struct {
		Devices []struct {
			Name     string `json:"Name"`
			DeviceId string `json:"DeviceId"`
			Version  string `json:"Version"`
			Vendor   string `json:"Vendor"`
			Releases []struct {
				Version     string   `json:"Version"`
				Description string   `json:"Description"`
				Uri         string   `json:"Uri"`
				Urgency     string   `json:"Urgency"` // "critical", "high", "medium", "low"
				Size        uint64   `json:"Size"`
				Flags       []string `json:"Flags"`
			} `json:"Releases"`
		} `json:"Devices"`
	}
	if err := json.Unmarshal(stdout, &raw); err != nil {
		slog.Warn("agenthealth: fwupdmgr json parse failed", "err", err, "exit", exit)
		return nil, nil
	}
	out := make([]*lmdmv1.FirmwareUpdate, 0)
	for _, d := range raw.Devices {
		if len(d.Releases) == 0 {
			continue
		}
		r := d.Releases[0]
		requiresReboot := false
		for _, f := range r.Flags {
			if f == "needs-reboot" {
				requiresReboot = true
				break
			}
		}
		out = append(out, &lmdmv1.FirmwareUpdate{
			DeviceName:       d.Name,
			DeviceId:         d.DeviceId,
			CurrentVersion:   d.Version,
			AvailableVersion: r.Version,
			Vendor:           d.Vendor,
			Severity:         r.Urgency,
			Description:      r.Description,
			ReleaseUrl:       r.Uri,
			SizeBytes:        r.Size,
			RequiresReboot:   requiresReboot,
		})
	}
	return out, nil
}
