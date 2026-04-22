// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package patchschedule stores and runs tenant-level / device-level patch
// schedules. The server-side Engine ticks every 60s and publishes
// ApplyPatchesCommand onto NATS when next_fire_at reaches now().
package patchschedule

import (
	"time"

	"github.com/google/uuid"
)

// Schedule mirrors the patch_schedules row (migration 0014).
// DeviceID is nil for tenant-wide schedules.
type Schedule struct {
	ID                    uuid.UUID
	TenantID              uuid.UUID
	DeviceID              *uuid.UUID
	CronExpr              string
	FilterSecurityOnly    bool
	FilterIncludePackages []string
	FilterExcludePackages []string
	Enabled               bool
	NextFireAt            time.Time
	LastRanAt             *time.Time
	LastRunStatus         *string
	SkippedRunsCount      int
	CreatedByUserID       *uuid.UUID
	CreatedAt             time.Time
}

// NewSchedule is the input form used by Create.
type NewSchedule struct {
	TenantID              uuid.UUID
	DeviceID              *uuid.UUID
	CronExpr              string
	FilterSecurityOnly    bool
	FilterIncludePackages []string
	FilterExcludePackages []string
	CreatedByUserID       *uuid.UUID
}

// RunStatus values mirror the DB CHECK constraint.
const (
	RunStatusOK                  = "ok"
	RunStatusSkippedMissedWindow = "skipped_missed_window"
	RunStatusPublishError        = "publish_error"
)

// RebootPolicy values (copied into ApplyPatchesCommand.reboot_policy).
const (
	RebootPolicyAdminOnly             = "admin_only"
	RebootPolicyImmediateAfterApply   = "immediate_after_apply"
	RebootPolicyNextMaintenanceWindow = "next_maintenance_window"
)
