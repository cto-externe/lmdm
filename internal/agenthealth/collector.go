// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"context"
	"log/slog"

	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// Collector orchestrates all sub-collectors and applies scoring.
// Sysfs roots and the disk lister are injectable so tests can replace them
// with fixtures. Production wires /sys/class/power_supply, /sys/class/hwmon,
// and the real listPhysicalDisks function.
type Collector struct {
	runner          CommandRunner
	powerSupplyRoot string
	hwmonRoot       string
	listDisks       func() ([]string, error) // nil → use the production listPhysicalDisks
}

// NewCollector returns a production-wired Collector.
func NewCollector(runner CommandRunner) *Collector {
	return &Collector{
		runner:          runner,
		powerSupplyRoot: "/sys/class/power_supply",
		hwmonRoot:       "/sys/class/hwmon",
	}
}

// NewCollectorWithRoots is for tests: inject sysfs fixture roots and an
// optional disk lister that returns canned device paths.
func NewCollectorWithRoots(runner CommandRunner, powerSupplyRoot, hwmonRoot string, listDisks func() ([]string, error)) *Collector {
	return &Collector{
		runner:          runner,
		powerSupplyRoot: powerSupplyRoot,
		hwmonRoot:       hwmonRoot,
		listDisks:       listDisks,
	}
}

// Collect runs every sub-collector, applies scoring, and returns a fully-populated
// HealthSnapshot. Missing tools and missing sensors produce WARN logs but never
// short-circuit collection — a partial snapshot is better than none.
func (c *Collector) Collect(ctx context.Context, deviceID string) *lmdmv1.HealthSnapshot {
	s := &lmdmv1.HealthSnapshot{
		DeviceId:  &lmdmv1.DeviceID{Id: deviceID},
		Timestamp: timestamppb.Now(),
	}
	disks, err := c.collectDisksWithLister(ctx)
	if err != nil {
		slog.Warn("agenthealth: disk collection failed", "err", err)
	}
	s.Disks = disks

	battery, err := collectBattery(c.powerSupplyRoot)
	if err != nil {
		slog.Warn("agenthealth: battery collection failed", "err", err)
	}
	s.Battery = battery

	s.Temperatures = collectTemperatures(c.hwmonRoot)

	fw, err := collectFirmware(ctx, c.runner)
	if err != nil {
		slog.Warn("agenthealth: firmware collection failed", "err", err)
	}
	s.FirmwareUpdates = fw

	applyHealthScore(s)
	return s
}

// collectDisksWithLister wraps collectDisks to use the injected lister when set.
func (c *Collector) collectDisksWithLister(ctx context.Context) ([]*lmdmv1.DiskHealth, error) {
	lister := c.listDisks
	if lister == nil {
		lister = listPhysicalDisks
	}
	return collectDisksFrom(ctx, c.runner, lister)
}
