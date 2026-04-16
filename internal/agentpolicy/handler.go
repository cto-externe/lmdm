// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agentpolicy receives ApplyProfileCommand messages from NATS,
// verifies the PQ signature, runs the policy executor, and publishes
// a ComplianceReport.
package agentpolicy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/distro"
	"github.com/cto-externe/lmdm/internal/policy"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

// Handler subscribes to fleet.agent.{deviceID}.commands and processes
// ApplyProfileCommand messages.
type Handler struct {
	nc        *nats.Conn
	serverPub *pqhybrid.SigningPublicKey
	registry  *policy.Registry
	deviceID  string
	snapRoot  string
	store     *ProfileStore
	pm        distro.PatchManager
	sub       *nats.Subscription
}

// NewHandler wires a Handler.
func NewHandler(nc *nats.Conn, serverPub *pqhybrid.SigningPublicKey, reg *policy.Registry, deviceID, snapRoot string, store *ProfileStore, pm distro.PatchManager) *Handler {
	return &Handler{
		nc:        nc,
		serverPub: serverPub,
		registry:  reg,
		deviceID:  deviceID,
		snapRoot:  snapRoot,
		store:     store,
		pm:        pm,
	}
}

// Start subscribes to the agent's command subject.
func (h *Handler) Start() error {
	subject := "fleet.agent." + h.deviceID + ".commands"
	sub, err := h.nc.Subscribe(subject, func(msg *nats.Msg) {
		h.handleMessage(msg)
	})
	if err != nil {
		return fmt.Errorf("agentpolicy: subscribe %s: %w", subject, err)
	}
	h.sub = sub
	return nil
}

// Stop unsubscribes.
func (h *Handler) Stop() {
	if h.sub != nil {
		_ = h.sub.Unsubscribe()
	}
}

func (h *Handler) handleMessage(msg *nats.Msg) {
	var env lmdmv1.CommandEnvelope
	if err := proto.Unmarshal(msg.Data, &env); err != nil {
		slog.Warn("agentpolicy: bad envelope", "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Dispatch by command type.
	switch {
	case env.GetApplyProfile() != nil:
		h.handleApplyProfile(ctx, msg.Data, &env)
	case env.GetRemoveProfile() != nil:
		h.handleRemoveProfile(ctx, env.GetRemoveProfile().GetProfileId().GetId())
	case env.GetApplyPatches() != nil:
		h.handleApplyPatches(ctx, env.GetApplyPatches())
	default:
		// Not a command we handle — ignore.
	}
}

func (h *Handler) handleApplyProfile(ctx context.Context, data []byte, env *lmdmv1.CommandEnvelope) {
	parsed, err := VerifyAndParseCommand(data, h.serverPub)
	if err != nil {
		slog.Warn("agentpolicy: verify/parse failed", "err", err)
		return
	}

	deploymentID := env.GetDeploymentId().GetId()
	if deploymentID == "" {
		deploymentID = env.GetCommandId()
	}

	_, actions, err := policy.ParseProfile(parsed.ProfileContent, h.registry)
	if err != nil {
		slog.Error("agentpolicy: parse profile", "err", err)
		return
	}

	result := policy.Execute(ctx, actions, h.snapRoot, deploymentID)

	if result.AllCompliant && parsed.ProfileID != "" {
		_ = h.store.Save(parsed.ProfileID, parsed.ProfileContent)
	}

	h.publishCompliance(result)
}

func (h *Handler) handleRemoveProfile(ctx context.Context, profileID string) {
	if profileID == "" {
		slog.Warn("agentpolicy: remove command with empty profile_id")
		return
	}

	// Attempt rollback from snapshot. The snapshot dir name convention matches
	// the deployment ID used during apply. For profiles applied via
	// ApplyProfileCommand, the deployment ID = command_id or profile_id.
	snapDir := filepath.Join(h.snapRoot, profileID)
	if _, err := os.Stat(snapDir); err == nil {
		if err := policy.Rollback(ctx, snapDir); err != nil {
			slog.Warn("agentpolicy: rollback on remove failed", "profile", profileID, "err", err)
		} else {
			slog.Info("agentpolicy: profile removed with rollback", "profile", profileID)
		}
	} else {
		slog.Warn("agentpolicy: no snapshot for profile, state is sticky", "profile", profileID)
	}

	// Remove from local store regardless.
	_ = h.store.Remove(profileID)

	// Publish compliance as unknown (profile removed, state may be mixed).
	h.publishComplianceStatus(lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_UNKNOWN, 0, 0, 0)
}

func (h *Handler) handleApplyPatches(ctx context.Context, cmd *lmdmv1.ApplyPatchesCommand) {
	if h.pm == nil {
		slog.Warn("agentpolicy: ApplyPatchesCommand received but no PatchManager configured")
		return
	}
	filter := distro.PatchFilter{}
	if cmd.GetFilter() != nil {
		filter.SecurityOnly = cmd.GetFilter().GetSecurityOnly()
		filter.IncludePackages = cmd.GetFilter().GetIncludePackages()
		filter.ExcludePackages = cmd.GetFilter().GetExcludePackages()
	}

	output, err := h.pm.ApplyUpdates(ctx, filter)
	if err != nil {
		slog.Error("agentpolicy: apply patches failed", "err", err, "output", output)
	} else {
		slog.Info("agentpolicy: patches applied successfully", "output_len", len(output))
	}

	// Re-detect updates after applying and publish a fresh PatchReport.
	h.publishPatchReport(ctx)
}

func (h *Handler) publishPatchReport(ctx context.Context) {
	if h.pm == nil {
		return
	}
	updates, reboot, err := h.pm.DetectUpdates(ctx)
	if err != nil {
		slog.Warn("agentpolicy: post-apply detect failed", "err", err)
		return
	}
	protoUpdates := make([]*lmdmv1.AvailableUpdate, 0, len(updates))
	for _, u := range updates {
		protoUpdates = append(protoUpdates, &lmdmv1.AvailableUpdate{
			Name: u.Name, CurrentVersion: u.CurrentVersion,
			AvailableVersion: u.AvailableVersion, Security: u.Security, Source: u.Source,
		})
	}
	report := &lmdmv1.PatchReport{
		DeviceId:       &lmdmv1.DeviceID{Id: h.deviceID},
		Timestamp:      timestamppb.New(time.Now().UTC()),
		Updates:        protoUpdates,
		RebootRequired: reboot,
	}
	data, err := proto.Marshal(report)
	if err != nil {
		return
	}
	_ = h.nc.Publish("fleet.agent."+h.deviceID+".patches", data)
}

func (h *Handler) publishCompliance(result policy.ExecutionResult) {
	status := lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT
	if !result.AllCompliant {
		status = lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT
	}
	var passed, failed uint32
	for _, ar := range result.Actions {
		if ar.Compliant {
			passed++
		} else {
			failed++
		}
	}
	h.publishComplianceStatus(status, uint32(len(result.Actions)), passed, failed)
}

func (h *Handler) publishComplianceStatus(status lmdmv1.ComplianceStatus, total, passed, failed uint32) {
	report := &lmdmv1.ComplianceReport{
		DeviceId:      &lmdmv1.DeviceID{Id: h.deviceID},
		Timestamp:     timestamppb.New(time.Now().UTC()),
		OverallStatus: status,
		TotalChecks:   total,
		PassedChecks:  passed,
		FailedChecks:  failed,
	}
	data, err := proto.Marshal(report)
	if err != nil {
		slog.Error("agentpolicy: marshal compliance", "err", err)
		return
	}
	subject := "fleet.agent." + h.deviceID + ".compliance"
	if err := h.nc.Publish(subject, data); err != nil {
		slog.Error("agentpolicy: publish compliance", "err", err)
	}
}

// extractRemoveProfileID parses a CommandEnvelope and returns the profile ID
// from a RemoveProfileCommand, or empty string if not a remove command.
func extractRemoveProfileID(data []byte) string {
	var env lmdmv1.CommandEnvelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return ""
	}
	rm := env.GetRemoveProfile()
	if rm == nil {
		return ""
	}
	return rm.GetProfileId().GetId()
}

// ParsedCommand is the result of verifying and extracting the
// ApplyProfileCommand from a CommandEnvelope.
type ParsedCommand struct {
	ProfileContent []byte
	ProfileID      string
	Version        string
}

// VerifyAndParseCommand unmarshals the CommandEnvelope, extracts the
// ApplyProfileCommand, and verifies the profile signature with the
// server's public key. Returns the profile content on success.
func VerifyAndParseCommand(data []byte, serverPub *pqhybrid.SigningPublicKey) (*ParsedCommand, error) {
	var env lmdmv1.CommandEnvelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	cmd := env.GetApplyProfile()
	if cmd == nil {
		return nil, fmt.Errorf("not an ApplyProfileCommand")
	}
	if cmd.ProfileSignature == nil || len(cmd.ProfileContent) == 0 {
		return nil, fmt.Errorf("missing profile content or signature")
	}

	sig := &pqhybrid.HybridSignature{
		Ed25519: cmd.ProfileSignature.Ed25519,
		MLDSA:   cmd.ProfileSignature.MlDsa,
	}
	if err := pqhybrid.Verify(serverPub, cmd.ProfileContent, sig); err != nil {
		return nil, fmt.Errorf("profile signature invalid: %w", err)
	}

	return &ParsedCommand{
		ProfileContent: cmd.ProfileContent,
		ProfileID:      cmd.GetProfileId().GetId(),
		Version:        cmd.GetVersion(),
	}, nil
}
