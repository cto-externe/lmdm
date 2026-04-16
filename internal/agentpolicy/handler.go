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
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
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
	sub       *nats.Subscription
}

// NewHandler wires a Handler.
func NewHandler(nc *nats.Conn, serverPub *pqhybrid.SigningPublicKey, reg *policy.Registry, deviceID, snapRoot string) *Handler {
	return &Handler{
		nc:        nc,
		serverPub: serverPub,
		registry:  reg,
		deviceID:  deviceID,
		snapRoot:  snapRoot,
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
	applyCmd := env.GetApplyProfile()
	if applyCmd == nil {
		return // not an ApplyProfileCommand — ignore
	}

	parsed, err := VerifyAndParseCommand(msg.Data, h.serverPub)
	if err != nil {
		slog.Warn("agentpolicy: verify/parse failed", "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

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

	h.publishCompliance(result)
}

func (h *Handler) publishCompliance(result policy.ExecutionResult) {
	status := lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT
	if !result.AllCompliant {
		status = lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT
	}

	report := &lmdmv1.ComplianceReport{
		DeviceId:      &lmdmv1.DeviceID{Id: h.deviceID},
		Timestamp:     timestamppb.New(time.Now().UTC()),
		OverallStatus: status,
		TotalChecks:   uint32(len(result.Actions)),
	}
	var passed, failed uint32
	for _, ar := range result.Actions {
		if ar.Compliant {
			passed++
		} else {
			failed++
		}
	}
	report.PassedChecks = passed
	report.FailedChecks = failed

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
