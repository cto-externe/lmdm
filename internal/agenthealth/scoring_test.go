// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func TestScoreDisk_SATA(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		disk *lmdmv1.DiskHealth
		want lmdmv1.HealthScore
	}{
		{
			name: "smart_failed_overrides_everything",
			disk: &lmdmv1.DiskHealth{
				Type:        "sata",
				SmartPassed: false,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					SelfTestPassed: true,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "reallocated_sectors_critical",
			disk: &lmdmv1.DiskHealth{
				Type:        "sata",
				SmartPassed: true,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					ReallocatedSectors: 1,
					SelfTestPassed:     true,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "pending_sectors_critical",
			disk: &lmdmv1.DiskHealth{
				Type:        "sata",
				SmartPassed: true,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					PendingSectors: 1,
					SelfTestPassed: true,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "uncorrectable_errors_critical",
			disk: &lmdmv1.DiskHealth{
				Type:        "sata",
				SmartPassed: true,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					UncorrectableErrors: 1,
					SelfTestPassed:      true,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "self_test_failed_critical",
			disk: &lmdmv1.DiskHealth{
				Type:        "sata",
				SmartPassed: true,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					SelfTestPassed: false,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "temp_warn_55",
			disk: &lmdmv1.DiskHealth{
				Type:               "sata",
				SmartPassed:        true,
				TemperatureCelsius: 55,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					SelfTestPassed: true,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "temp_warn_64",
			disk: &lmdmv1.DiskHealth{
				Type:               "sata",
				SmartPassed:        true,
				TemperatureCelsius: 64,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					SelfTestPassed: true,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "temp_critical_65",
			disk: &lmdmv1.DiskHealth{
				Type:               "sata",
				SmartPassed:        true,
				TemperatureCelsius: 65,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					SelfTestPassed: true,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "healthy",
			disk: &lmdmv1.DiskHealth{
				Type:               "sata",
				SmartPassed:        true,
				TemperatureCelsius: 35,
				SataAttributes: &lmdmv1.SATASmartAttributes{
					SelfTestPassed: true,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_GREEN,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scoreDisk(tc.disk)
			if got != tc.want {
				t.Fatalf("scoreDisk = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScoreDisk_NVMe(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		disk *lmdmv1.DiskHealth
		want lmdmv1.HealthScore
	}{
		{
			name: "critical_warning_nonzero",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					CriticalWarning: 1,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "percent_used_100_critical",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					PercentageUsed: 100,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "percent_used_80_warn",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					PercentageUsed: 80,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "percent_used_99_warn",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					PercentageUsed: 99,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "percent_used_79_ok",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					PercentageUsed: 79,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_GREEN,
		},
		{
			name: "media_errors_1_warn",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					MediaErrors: 1,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "media_errors_10_critical",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					MediaErrors: 10,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "available_spare_below_threshold_warn",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					AvailableSparePct:       5,
					AvailableSpareThreshold: 10,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "available_spare_threshold_zero_no_warn",
			disk: &lmdmv1.DiskHealth{
				Type:        "nvme",
				SmartPassed: true,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					AvailableSparePct:       0,
					AvailableSpareThreshold: 0,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_GREEN,
		},
		{
			name: "healthy",
			disk: &lmdmv1.DiskHealth{
				Type:               "nvme",
				SmartPassed:        true,
				TemperatureCelsius: 40,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					PercentageUsed:          5,
					AvailableSparePct:       100,
					AvailableSpareThreshold: 10,
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_GREEN,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scoreDisk(tc.disk)
			if got != tc.want {
				t.Fatalf("scoreDisk = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScoreBattery(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		battery *lmdmv1.BatteryHealth
		want    lmdmv1.HealthScore
	}{
		{
			name: "health_pct_49_critical",
			battery: &lmdmv1.BatteryHealth{
				Present:   true,
				HealthPct: 49,
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "health_pct_79_warn",
			battery: &lmdmv1.BatteryHealth{
				Present:   true,
				HealthPct: 79,
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "health_pct_50_warn",
			battery: &lmdmv1.BatteryHealth{
				Present:   true,
				HealthPct: 50,
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "health_pct_80_ok",
			battery: &lmdmv1.BatteryHealth{
				Present:   true,
				HealthPct: 80,
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_GREEN,
		},
		{
			name: "cycles_above_warn",
			battery: &lmdmv1.BatteryHealth{
				Present:    true,
				HealthPct:  95,
				CycleCount: 1500,
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "health_pct_zero_unknown_no_penalty",
			battery: &lmdmv1.BatteryHealth{
				Present:    true,
				HealthPct:  0,
				CycleCount: 50,
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_GREEN,
		},
		{
			name: "healthy",
			battery: &lmdmv1.BatteryHealth{
				Present:    true,
				HealthPct:  92,
				CycleCount: 200,
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_GREEN,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scoreBattery(tc.battery)
			if got != tc.want {
				t.Fatalf("scoreBattery = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScoreBattery_AbsentNotPenalized(t *testing.T) {
	t.Parallel()

	// applyHealthScore must skip a battery whose Present=false (e.g. desktop)
	// and not downgrade the overall score.
	s := &lmdmv1.HealthSnapshot{
		Battery: &lmdmv1.BatteryHealth{
			Present:   false,
			HealthPct: 5, // would be RED if it counted
		},
	}
	applyHealthScore(s)
	if s.OverallScore != lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED {
		t.Fatalf("overall = %v, want UNSPECIFIED for absent battery", s.OverallScore)
	}
	if s.Battery.Score != lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED {
		t.Fatalf("battery score should not have been computed, got %v", s.Battery.Score)
	}
}

func TestScoreTemperatures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		tr   *lmdmv1.TemperatureReadings
		want lmdmv1.HealthScore
	}{
		{
			name: "nil_unspecified",
			tr:   nil,
			want: lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED,
		},
		{
			name: "cpu_above_default_critical",
			tr: &lmdmv1.TemperatureReadings{
				Cpu: []*lmdmv1.TemperatureSensor{
					{Label: "Core 0", TemperatureCelsius: 95},
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "cpu_above_default_warn",
			tr: &lmdmv1.TemperatureReadings{
				Cpu: []*lmdmv1.TemperatureSensor{
					{Label: "Core 0", TemperatureCelsius: 85},
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "per_sensor_critical_threshold_overrides",
			tr: &lmdmv1.TemperatureReadings{
				Cpu: []*lmdmv1.TemperatureSensor{
					// 90 would be ORANGE under defaults, but the sensor advertises
					// 80 as its critical threshold so it must be RED.
					{Label: "Core 0", TemperatureCelsius: 90, CriticalThreshold: 80},
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "per_sensor_high_threshold_overrides",
			tr: &lmdmv1.TemperatureReadings{
				Cpu: []*lmdmv1.TemperatureSensor{
					// 70 would be GREEN under defaults, but the sensor advertises
					// 60 as its high threshold so it must be ORANGE.
					{Label: "Core 0", TemperatureCelsius: 70, HighThreshold: 60, CriticalThreshold: 100},
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "healthy",
			tr: &lmdmv1.TemperatureReadings{
				Cpu: []*lmdmv1.TemperatureSensor{
					{Label: "Core 0", TemperatureCelsius: 45},
					{Label: "Core 1", TemperatureCelsius: 47},
				},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_GREEN,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scoreTemperatures(tc.tr)
			if got != tc.want {
				t.Fatalf("scoreTemperatures = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScoreFirmware(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		updates []*lmdmv1.FirmwareUpdate
		want    lmdmv1.HealthScore
	}{
		{
			name:    "empty_unspecified",
			updates: nil,
			want:    lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED,
		},
		{
			name: "critical",
			updates: []*lmdmv1.FirmwareUpdate{
				{DeviceName: "BIOS", Severity: "critical"},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
		{
			name: "high",
			updates: []*lmdmv1.FirmwareUpdate{
				{DeviceName: "TPM", Severity: "high"},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_ORANGE,
		},
		{
			name: "medium_no_impact",
			updates: []*lmdmv1.FirmwareUpdate{
				{DeviceName: "TPM", Severity: "medium"},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED,
		},
		{
			name: "low_no_impact",
			updates: []*lmdmv1.FirmwareUpdate{
				{DeviceName: "Dock", Severity: "low"},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED,
		},
		{
			name: "missing_severity_no_impact",
			updates: []*lmdmv1.FirmwareUpdate{
				{DeviceName: "Unknown", Severity: ""},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_UNSPECIFIED,
		},
		{
			name: "high_then_critical_returns_critical",
			updates: []*lmdmv1.FirmwareUpdate{
				{DeviceName: "TPM", Severity: "high"},
				{DeviceName: "BIOS", Severity: "critical"},
			},
			want: lmdmv1.HealthScore_HEALTH_SCORE_RED,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := scoreFirmware(tc.updates)
			if got != tc.want {
				t.Fatalf("scoreFirmware = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyHealthScore_OverallIsWorstOfComponents(t *testing.T) {
	t.Parallel()

	// disk OK + battery ORANGE + firmware RED → overall must be RED.
	s := &lmdmv1.HealthSnapshot{
		Disks: []*lmdmv1.DiskHealth{
			{
				Name:               "nvme0n1",
				Type:               "nvme",
				SmartPassed:        true,
				TemperatureCelsius: 40,
				NvmeSmartLog: &lmdmv1.NVMeSmartLog{
					PercentageUsed:          5,
					AvailableSparePct:       100,
					AvailableSpareThreshold: 10,
				},
			},
		},
		Battery: &lmdmv1.BatteryHealth{
			Present:   true,
			HealthPct: 79, // → ORANGE
		},
		FirmwareUpdates: []*lmdmv1.FirmwareUpdate{
			{DeviceName: "BIOS", Severity: "critical"}, // → RED
		},
	}

	applyHealthScore(s)

	if got, want := s.Disks[0].Score, lmdmv1.HealthScore_HEALTH_SCORE_GREEN; got != want {
		t.Errorf("disk score = %v, want %v", got, want)
	}
	if got, want := s.Battery.Score, lmdmv1.HealthScore_HEALTH_SCORE_ORANGE; got != want {
		t.Errorf("battery score = %v, want %v", got, want)
	}
	if got, want := s.OverallScore, lmdmv1.HealthScore_HEALTH_SCORE_RED; got != want {
		t.Errorf("overall = %v, want %v", got, want)
	}
}

func TestApplyHealthScore_AllHealthyIsGreen(t *testing.T) {
	t.Parallel()

	s := &lmdmv1.HealthSnapshot{
		Disks: []*lmdmv1.DiskHealth{
			{
				Name:               "sda",
				Type:               "sata",
				SmartPassed:        true,
				TemperatureCelsius: 30,
				SataAttributes:     &lmdmv1.SATASmartAttributes{SelfTestPassed: true},
			},
		},
		Battery: &lmdmv1.BatteryHealth{
			Present:    true,
			HealthPct:  95,
			CycleCount: 100,
		},
		Temperatures: &lmdmv1.TemperatureReadings{
			Cpu: []*lmdmv1.TemperatureSensor{
				{Label: "Core 0", TemperatureCelsius: 45},
			},
		},
	}

	applyHealthScore(s)

	if s.OverallScore != lmdmv1.HealthScore_HEALTH_SCORE_GREEN {
		t.Fatalf("overall = %v, want GREEN", s.OverallScore)
	}
}
