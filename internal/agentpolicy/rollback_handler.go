// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agentstate"
	"github.com/cto-externe/lmdm/internal/policy"
)

// RollbackHandler processes RollbackCommand messages by invoking the central
// policy.Rollback against the snapshot directory for the given deployment,
// publishing a CommandResult on the COMMAND_RESULTS subject, and clearing
// the agentstate pending row if it matches.
type RollbackHandler struct {
	publisher ResultPublisher
	state     *agentstate.Store
	snapRoot  string // typically /var/lib/lmdm/snapshots
	deviceID  string
}

// ResultPublisher is the minimal interface the handler needs to send a result.
// The production implementation publishes on NATS (JetStream or core — the
// watchdog-level ack semantics live in the Apply handler, not here).
type ResultPublisher interface {
	Publish(subject string, data []byte) error
}

// NewRollbackHandler wires a RollbackHandler.
func NewRollbackHandler(publisher ResultPublisher, state *agentstate.Store, snapRoot, deviceID string) *RollbackHandler {
	return &RollbackHandler{publisher: publisher, state: state, snapRoot: snapRoot, deviceID: deviceID}
}

// Handle processes a single RollbackCommand. Never returns an error — all
// failures are reported via CommandResult{Success: false, Error: ...}.
func (h *RollbackHandler) Handle(ctx context.Context, commandID string, cmd *lmdmv1.RollbackCommand) {
	start := time.Now()
	deploymentID := cmd.GetDeploymentId().GetId()
	snapDir := filepath.Join(h.snapRoot, deploymentID)

	result := &lmdmv1.CommandResult{
		CommandId:    commandID,
		DeviceId:     &lmdmv1.DeviceID{Id: h.deviceID},
		Timestamp:    timestamppb.Now(),
		DeploymentId: cmd.GetDeploymentId(),
		SnapshotId:   cmd.GetSnapshotId(),
	}

	if deploymentID == "" {
		result.Success = false
		result.Error = "rollback: empty deployment_id"
		h.publish(result)
		return
	}

	if err := policy.Rollback(ctx, snapDir); err != nil {
		slog.Error("agentpolicy: rollback failed", "deployment_id", deploymentID, "snap_dir", snapDir, "err", err)
		result.Success = false
		result.Error = err.Error()
	} else {
		slog.Info("agentpolicy: rollback succeeded", "deployment_id", deploymentID, "snap_dir", snapDir)
		result.Success = true
	}

	// Clear the pending row if it matches the rolled-back deployment.
	if h.state != nil {
		if pending, err := h.state.GetPending(); err == nil && pending != nil && pending.DeploymentID == deploymentID {
			if err := h.state.ClearPending(); err != nil {
				slog.Warn("agentpolicy: clear pending failed", "err", err)
			}
		}
	}

	result.DurationMs = uint32(time.Since(start).Milliseconds()) //nolint:gosec // bounded by timeout

	h.publish(result)
}

func (h *RollbackHandler) publish(result *lmdmv1.CommandResult) {
	subject := "fleet.agent." + h.deviceID + ".command-result"
	data, err := proto.Marshal(result)
	if err != nil {
		slog.Error("agentpolicy: marshal CommandResult failed", "err", err)
		return
	}
	if err := h.publisher.Publish(subject, data); err != nil {
		slog.Warn("agentpolicy: publish CommandResult failed", "subject", subject, "err", err)
	}
}
