// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package deployments

import "github.com/google/uuid"

// Event is the sealed interface of all inputs the Engine state machine handles.
// Concrete event types are defined in this file; each transition the Engine
// can make is triggered by one of them.
type Event interface{ isDeploymentEvent() }

// DeviceResult is emitted by the COMMAND_RESULTS consumer when an agent reports
// the outcome of an ApplyProfileCommand (canary or rollout) or a
// RollbackCommand. The Engine uses it to record per-device status and to
// advance the deployment state.
type DeviceResult struct {
	DeploymentID       uuid.UUID
	DeviceID           uuid.UUID
	Success            bool
	RolledBack         bool
	HealthCheckResults []byte // JSONB bytes of the agent's health_checks array
	ErrorMessage       string
	SnapshotID         string
}

func (DeviceResult) isDeploymentEvent() {}

// Validate is posted by POST /deployments/{id}/validate when an operator (or
// the semi-auto timer via ValidationTimeout) accepts the canary result and
// unblocks the rollout to the remaining targets.
type Validate struct {
	DeploymentID uuid.UUID
	ByUserID     uuid.UUID
}

func (Validate) isDeploymentEvent() {}

// Rollback is posted by POST /deployments/{id}/rollback and instructs the
// Engine to push a RollbackCommand to every device that has observed a
// successful (or still-applying) apply, then transition the deployment to the
// ROLLED_BACK terminal state.
type Rollback struct {
	DeploymentID uuid.UUID
	ByUserID     uuid.UUID
	Reason       string
}

func (Rollback) isDeploymentEvent() {}

// ValidationTimeout is emitted by the per-deployment time.AfterFunc installed
// in semi_auto mode. When it fires while the deployment is still in
// AWAITING_VALIDATION, the Engine auto-validates and proceeds to ROLLING_OUT.
type ValidationTimeout struct {
	DeploymentID uuid.UUID
}

func (ValidationTimeout) isDeploymentEvent() {}
