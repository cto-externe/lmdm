// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// Scoring thresholds. Hard-coded for the MVP; exposed as named constants so
// the rationale is visible to operators reading the code. Post-MVP: load from
// a YAML config if field feedback justifies per-deployment tuning.
const (
	// Disk (SATA) — any of these attributes being non-zero is a drive that
	// has started failing. Reallocated sectors in particular are irreversible.
	sataReallocatedWarn   = 0 // any reallocation → RED immediately
	sataPendingWarn       = 0
	sataUncorrectableWarn = 0

	// Disk temperature: manufacturers rate drives for 55-60°C; sustained
	// operation above that shortens life substantially.
	diskTempWarnCelsius = 55
	diskTempCritCelsius = 65

	// NVMe percent_used: indicative of wear. Spec permits values > 100
	// (over-provisioning exhausted); 100 is the nominal "end of warranted life".
	nvmePercentUsedWarn = 80
	nvmePercentUsedCrit = 100

	// NVMe media errors: any is concerning. Industry consensus treats >10
	// as "replace soon".
	nvmeMediaErrorsWarn = 1
	nvmeMediaErrorsCrit = 10

	// Battery: OEM-rated retention is typically 80% after 500 cycles.
	batteryHealthPctWarn = 80
	batteryHealthPctCrit = 50
	batteryCyclesWarn    = 1000

	// CPU temperature: 85°C sustained is a throttle trigger on most Intel
	// and AMD consumer parts; the per-sensor `critical_threshold` overrides
	// this when present.
	cpuTempWarnCelsius = 85
	cpuTempCritCelsius = 95
)

// applyHealthScore computes per-component HealthScore values and sets the
// snapshot's OverallScore to the worst of all components.
//
// Score ordering (defined by the proto enum):
//
//	UNSPECIFIED (0) < GREEN (1) < ORANGE (2) < RED (3)
//
// A missing component (no battery, no firmware updates, no temperature
// sensors) does not penalize the score — the worst stays at UNSPECIFIED, and
// when no component contributes anything we leave OverallScore at
// UNSPECIFIED rather than coercing to GREEN. The collector seeds the
// snapshot with at least one disk in normal operation, so the practical
// result is GREEN/ORANGE/RED depending on actual signals.
func applyHealthScore(s *lmdmv1.HealthSnapshot) {
	var worst lmdmv1.HealthScore

	for _, d := range s.Disks {
		d.Score = scoreDisk(d)
		worst = max(worst, d.Score)
	}
	if s.Battery != nil && s.Battery.Present {
		s.Battery.Score = scoreBattery(s.Battery)
		worst = max(worst, s.Battery.Score)
	}
	worst = max(worst, scoreTemperatures(s.Temperatures))
	worst = max(worst, scoreFirmware(s.FirmwareUpdates))

	s.OverallScore = worst
}

// scoreDisk evaluates a single disk's HealthScore using SMART overall status,
// SATA-specific failure attributes (reallocated/pending/uncorrectable, last
// self-test), NVMe-specific wear and error counters, and disk temperature.
func scoreDisk(d *lmdmv1.DiskHealth) lmdmv1.HealthScore {
	if !d.SmartPassed {
		return lmdmv1.HealthScore_HEALTH_SCORE_RED
	}
	if d.Type == "sata" && d.SataAttributes != nil {
		a := d.SataAttributes
		if a.ReallocatedSectors > sataReallocatedWarn ||
			a.PendingSectors > sataPendingWarn ||
			a.UncorrectableErrors > sataUncorrectableWarn ||
			!a.SelfTestPassed {
			return lmdmv1.HealthScore_HEALTH_SCORE_RED
		}
	}
	if d.Type == "nvme" && d.NvmeSmartLog != nil {
		n := d.NvmeSmartLog
		if n.CriticalWarning != 0 ||
			n.MediaErrors >= nvmeMediaErrorsCrit ||
			n.PercentageUsed >= nvmePercentUsedCrit {
			return lmdmv1.HealthScore_HEALTH_SCORE_RED
		}
		if n.PercentageUsed >= nvmePercentUsedWarn ||
			n.MediaErrors >= nvmeMediaErrorsWarn ||
			(n.AvailableSpareThreshold > 0 && n.AvailableSparePct < n.AvailableSpareThreshold) {
			return lmdmv1.HealthScore_HEALTH_SCORE_ORANGE
		}
	}
	if d.TemperatureCelsius >= diskTempCritCelsius {
		return lmdmv1.HealthScore_HEALTH_SCORE_RED
	}
	if d.TemperatureCelsius >= diskTempWarnCelsius {
		return lmdmv1.HealthScore_HEALTH_SCORE_ORANGE
	}
	return lmdmv1.HealthScore_HEALTH_SCORE_GREEN
}

// scoreBattery evaluates battery wear from the (full / design) ratio and the
// charge cycle count. A HealthPct of 0 is treated as "unknown" (the upower
// collector emits 0 when it cannot read the design capacity) and does not
// downgrade the score.
func scoreBattery(b *lmdmv1.BatteryHealth) lmdmv1.HealthScore {
	if b.HealthPct > 0 && b.HealthPct < batteryHealthPctCrit {
		return lmdmv1.HealthScore_HEALTH_SCORE_RED
	}
	if (b.HealthPct > 0 && b.HealthPct < batteryHealthPctWarn) ||
		b.CycleCount > batteryCyclesWarn {
		return lmdmv1.HealthScore_HEALTH_SCORE_ORANGE
	}
	return lmdmv1.HealthScore_HEALTH_SCORE_GREEN
}

// scoreTemperatures evaluates CPU sensors against per-sensor thresholds when
// present, falling back to package-wide defaults. GPU and other sensors are
// left out of the score for the MVP — they are still emitted in the snapshot
// for display, but the lack of a stable cross-vendor critical threshold for
// GPU thermals would generate too many false positives at this stage.
func scoreTemperatures(tr *lmdmv1.TemperatureReadings) lmdmv1.HealthScore {
	if tr == nil {
		return lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED
	}
	var worst lmdmv1.HealthScore
	for _, s := range tr.Cpu {
		crit := int32(cpuTempCritCelsius)
		warn := int32(cpuTempWarnCelsius)
		if s.CriticalThreshold > 0 {
			crit = s.CriticalThreshold
		}
		if s.HighThreshold > 0 {
			warn = s.HighThreshold
		}
		if s.TemperatureCelsius >= crit {
			return lmdmv1.HealthScore_HEALTH_SCORE_RED
		}
		if s.TemperatureCelsius >= warn {
			worst = max(worst, lmdmv1.HealthScore_HEALTH_SCORE_ORANGE)
		} else {
			worst = max(worst, lmdmv1.HealthScore_HEALTH_SCORE_GREEN)
		}
	}
	return worst
}

// scoreFirmware maps fwupd severity strings to HealthScore. Anything below
// "high" (medium, low, missing) is treated as informational and does not
// affect the score — operators see those updates in the snapshot, but they
// don't generate alerts.
func scoreFirmware(updates []*lmdmv1.FirmwareUpdate) lmdmv1.HealthScore {
	var worst lmdmv1.HealthScore
	for _, f := range updates {
		switch f.Severity {
		case "critical":
			return lmdmv1.HealthScore_HEALTH_SCORE_RED
		case "high":
			worst = max(worst, lmdmv1.HealthScore_HEALTH_SCORE_ORANGE)
		}
	}
	return worst
}
