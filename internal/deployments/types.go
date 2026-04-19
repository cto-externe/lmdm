// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package deployments models the canary + rollout state machine and persists
// it in PostgreSQL via the deployments and deployment_results tables.
package deployments

import (
	"time"

	"github.com/google/uuid"
)

// Status is the deployment-level state.
type Status string

// Deployment-level status values. They mirror the CHECK constraint on
// deployments.status in migration 0012.
const (
	StatusPlanned            Status = "planned"
	StatusCanaryRunning      Status = "canary_running"
	StatusCanaryOK           Status = "canary_ok"
	StatusCanaryFailed       Status = "canary_failed"
	StatusAwaitingValidation Status = "awaiting_validation"
	StatusRollingOut         Status = "rolling_out"
	StatusCompleted          Status = "completed"
	StatusPartiallyFailed    Status = "partially_failed"
	StatusRolledBack         Status = "rolled_back"
)

// IsValid reports whether s is one of the known statuses.
func (s Status) IsValid() bool {
	switch s {
	case StatusPlanned, StatusCanaryRunning, StatusCanaryOK, StatusCanaryFailed,
		StatusAwaitingValidation, StatusRollingOut, StatusCompleted,
		StatusPartiallyFailed, StatusRolledBack:
		return true
	}
	return false
}

// IsTerminal reports whether s is a terminal state (no transitions allowed).
func (s Status) IsTerminal() bool {
	return s == StatusCompleted || s == StatusPartiallyFailed || s == StatusRolledBack
}

// ValidationMode controls how the server gates the rollout phase after a
// successful canary.
type ValidationMode string

// Validation mode values mirror the CHECK constraint on
// deployments.validation_mode.
const (
	ModeManual   ValidationMode = "manual"
	ModeSemiAuto ValidationMode = "semi_auto"
	ModeAuto     ValidationMode = "auto"
)

// IsValid reports whether m is a known validation mode.
func (m ValidationMode) IsValid() bool {
	return m == ModeManual || m == ModeSemiAuto || m == ModeAuto
}

// Deployment mirrors the deployments table row.
type Deployment struct {
	ID                       uuid.UUID
	TenantID                 uuid.UUID
	ProfileID                uuid.UUID
	TargetGroupID            *uuid.UUID
	TargetDeviceIDs          []uuid.UUID
	CanaryDeviceID           uuid.UUID
	Status                   Status
	ValidationMode           ValidationMode
	ValidationTimeoutSeconds int
	FailureThresholdPct      int
	CreatedByUserID          *uuid.UUID
	CreatedAt                time.Time
	CanaryStartedAt          *time.Time
	CanaryFinishedAt         *time.Time
	ValidatedAt              *time.Time
	CompletedAt              *time.Time
	Reason                   string
}

// ResultStatus is the per-device deployment outcome.
type ResultStatus string

// Per-device result status values; mirror the CHECK constraint on
// deployment_results.status.
const (
	ResultPending    ResultStatus = "pending"
	ResultApplying   ResultStatus = "applying"
	ResultSuccess    ResultStatus = "success"
	ResultFailed     ResultStatus = "failed"
	ResultRolledBack ResultStatus = "rolled_back"
)

// IsValid reports whether r is one of the known per-device result statuses.
func (r ResultStatus) IsValid() bool {
	switch r {
	case ResultPending, ResultApplying, ResultSuccess, ResultFailed, ResultRolledBack:
		return true
	}
	return false
}

// Result mirrors the deployment_results table row.
type Result struct {
	ID                 uuid.UUID
	TenantID           uuid.UUID
	DeploymentID       uuid.UUID
	DeviceID           uuid.UUID
	IsCanary           bool
	Status             ResultStatus
	SnapshotID         string
	HealthCheckResults []byte // JSONB raw bytes
	ErrorMessage       string
	AppliedAt          *time.Time
	RolledBackAt       *time.Time
}

// ListFilter narrows the result set of Repository.List. A zero-value filter
// returns every deployment for the tenant (up to the default limit).
type ListFilter struct {
	Status Status // empty == no filter
	Limit  int
	Offset int
}
