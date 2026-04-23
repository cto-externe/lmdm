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
	"github.com/cto-externe/lmdm/internal/agenthealthcheck"
	"github.com/cto-externe/lmdm/internal/agentsession"
	"github.com/cto-externe/lmdm/internal/agentstate"
	"github.com/cto-externe/lmdm/internal/distro"
	"github.com/cto-externe/lmdm/internal/policy"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

// JetStream is the minimal surface needed for publishing CommandResult with
// ack. Production impl is a thin wrapper around jetstream.JetStream.Publish.
type JetStream interface {
	PublishWithAck(ctx context.Context, subject string, data []byte) error
}

// Handler subscribes to fleet.agent.{deviceID}.commands and processes
// ApplyProfileCommand, RemoveProfileCommand, ApplyPatchesCommand,
// RollbackCommand, RunHealthCheckCommand, and RebootCommand messages.
type Handler struct {
	nc        *nats.Conn
	serverPub *pqhybrid.SigningPublicKey
	registry  *policy.Registry
	deviceID  string
	snapRoot  string
	store     *ProfileStore
	pm        distro.PatchManager
	sub       *nats.Subscription

	js              JetStream
	state           *agentstate.Store
	hcRunner        HealthCheckRunner
	rollbackHandler *RollbackHandler
	hcHandler       *HealthCheckHandler
	ackTimeout      time.Duration

	session       *agentsession.Checker
	rebootExec    RebootExecutor
	maxDeferCount int // defaults to 3 when 0
}

// HandlerOptions groups the dependencies for NewHandler. Optional deps (JS,
// State, HCRunner, Session, RebootExec) may be nil — the handler degrades
// gracefully.
type HandlerOptions struct {
	NC         *nats.Conn
	ServerPub  *pqhybrid.SigningPublicKey
	Registry   *policy.Registry
	DeviceID   string
	SnapRoot   string
	Store      *ProfileStore
	PM         distro.PatchManager
	JS         JetStream
	State      *agentstate.Store
	HCRunner   HealthCheckRunner
	AckTimeout time.Duration

	Session       *agentsession.Checker
	RebootExec    RebootExecutor
	MaxDeferCount int
}

// NewHandler wires a Handler.
func NewHandler(opts HandlerOptions) *Handler {
	h := &Handler{
		nc:            opts.NC,
		serverPub:     opts.ServerPub,
		registry:      opts.Registry,
		deviceID:      opts.DeviceID,
		snapRoot:      opts.SnapRoot,
		store:         opts.Store,
		pm:            opts.PM,
		js:            opts.JS,
		state:         opts.State,
		hcRunner:      opts.HCRunner,
		ackTimeout:    opts.AckTimeout,
		session:       opts.Session,
		rebootExec:    opts.RebootExec,
		maxDeferCount: opts.MaxDeferCount,
	}
	if h.ackTimeout == 0 {
		h.ackTimeout = 10 * time.Second
	}
	pub := &natsCorePublisher{nc: opts.NC}
	h.rollbackHandler = NewRollbackHandler(pub, opts.State, opts.SnapRoot, opts.DeviceID)
	if opts.HCRunner != nil {
		h.hcHandler = NewHealthCheckHandler(pub, opts.HCRunner, opts.DeviceID)
	}
	return h
}

// natsCorePublisher adapts *nats.Conn to ResultPublisher.
type natsCorePublisher struct{ nc *nats.Conn }

func (p *natsCorePublisher) Publish(subject string, data []byte) error {
	if p.nc == nil {
		return fmt.Errorf("no nats connection")
	}
	return p.nc.Publish(subject, data)
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
	case env.GetReboot() != nil:
		h.handleRebootCommand(ctx, env.GetReboot())
	case env.GetRollback() != nil:
		if h.rollbackHandler != nil {
			h.rollbackHandler.Handle(ctx, env.GetCommandId(), env.GetRollback())
		}
	case env.GetRunHealthCheck() != nil:
		if h.hcHandler != nil {
			h.hcHandler.Handle(ctx, env.GetCommandId(), env.GetRunHealthCheck())
		}
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

	// Inject device variables into file_template actions before Apply.
	// SiteID/GroupIDs stay empty for MVP (agent doesn't yet track those).
	InjectTemplateVars(actions, h.deviceID, parsed.TenantID)

	snapDir := filepath.Join(h.snapRoot, deploymentID)

	// 1. Persist pending BEFORE Apply (watchdog marker).
	if h.state != nil {
		if err := h.state.SetPending(agentstate.PendingDeployment{
			DeploymentID: deploymentID,
			ProfileID:    parsed.ProfileID,
			SnapDir:      snapDir,
			StartedAt:    time.Now(),
		}); err != nil {
			slog.Warn("agentpolicy: set pending failed", "err", err)
		}
	}

	// 2. Run the executor.
	result := policy.Execute(ctx, actions, h.snapRoot, deploymentID)

	// 3. Run built-in health checks after apply.
	var hcResults []agenthealthcheck.HealthCheckResult
	if h.hcRunner != nil {
		hcResults = h.hcRunner.RunBuiltins(ctx)
	}
	anyHCFailed := false
	for _, r := range hcResults {
		if !r.Passed {
			anyHCFailed = true
			break
		}
	}

	// 4. Build a CommandResult proto for server consumption.
	cmdResult := &lmdmv1.CommandResult{
		CommandId:    env.GetCommandId(),
		DeviceId:     &lmdmv1.DeviceID{Id: h.deviceID},
		Timestamp:    timestamppb.Now(),
		DeploymentId: env.GetDeploymentId(),
		IsCanary:     env.GetIsCanary(),
		SnapshotId:   deploymentID,
	}
	for _, r := range hcResults {
		cmdResult.HealthChecks = append(cmdResult.HealthChecks, &lmdmv1.HealthCheckResult{
			Name: r.Name, Passed: r.Passed, Detail: r.Detail,
		})
	}

	applySuccess := result.AllCompliant

	// 5. Failure path: rollback + best-effort publish + clear pending.
	if !applySuccess || anyHCFailed {
		if rbErr := policy.Rollback(ctx, snapDir); rbErr != nil {
			slog.Warn("agentpolicy: rollback after failed apply/hc returned error", "err", rbErr)
		}
		cmdResult.Success = false
		if !applySuccess {
			cmdResult.Error = "apply failed"
		} else {
			cmdResult.Error = "health checks failed"
		}
		h.publishResultBestEffort(cmdResult)
		if h.state != nil {
			if err := h.state.ClearPending(); err != nil {
				slog.Warn("agentpolicy: clear pending after failure", "err", err)
			}
		}
		h.publishCompliance(result)
		return
	}

	// 6. Success path: publish with ack on JetStream.
	cmdResult.Success = true

	ackCtx, cancel := context.WithTimeout(ctx, h.ackTimeout)
	defer cancel()
	if err := h.publishResultWithAck(ackCtx, cmdResult); err != nil {
		slog.Warn("agentpolicy: ack timeout / error, rolling back", "err", err)
		if rbErr := policy.Rollback(ctx, snapDir); rbErr != nil {
			slog.Warn("agentpolicy: watchdog rollback error", "err", rbErr)
		}
		cmdResult.Success = false
		cmdResult.Error = "ack timeout: " + err.Error()
		h.publishResultBestEffort(cmdResult)
		// Keep pending for boot-time watchdog to re-attempt if we survive.
		h.publishCompliance(result)
		return
	}

	// Ack received — clear pending and save profile.
	if h.state != nil {
		if err := h.state.ClearPending(); err != nil {
			slog.Warn("agentpolicy: clear pending after ack", "err", err)
		}
	}
	if parsed.ProfileID != "" {
		_ = h.store.Save(parsed.ProfileID, parsed.ProfileContent)
	}
	h.publishCompliance(result)
}

// publishResultWithAck publishes the CommandResult on the COMMAND_RESULTS
// JetStream subject and waits for the server-side ack (reliable delivery).
func (h *Handler) publishResultWithAck(ctx context.Context, result *lmdmv1.CommandResult) error {
	if h.js == nil {
		return fmt.Errorf("no jetstream wired")
	}
	data, err := proto.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal CommandResult: %w", err)
	}
	subject := "fleet.agent." + h.deviceID + ".command-result"
	return h.js.PublishWithAck(ctx, subject, data)
}

// publishResultBestEffort publishes via core NATS (no ack). Used for failure
// paths where we've already decided to roll back — we want the server to see
// the result eventually but don't block on it.
func (h *Handler) publishResultBestEffort(result *lmdmv1.CommandResult) {
	if h.nc == nil {
		return
	}
	data, err := proto.Marshal(result)
	if err != nil {
		return
	}
	subject := "fleet.agent." + h.deviceID + ".command-result"
	_ = h.nc.Publish(subject, data)
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
	rebootRequired, _ := h.publishPatchReport(ctx)

	// Chain a reboot when the server requested it and the kernel needs one.
	// "immediate_after_apply" is defined server-side in the patchschedule
	// package; we use the raw string here so the agent has no dependency on
	// server packages.
	if cmd.GetRebootPolicy() == "immediate_after_apply" && rebootRequired {
		h.handleRebootCommand(ctx, &lmdmv1.RebootCommand{
			Reason:             "immediate_after_patch",
			GracePeriodSeconds: 300,
			Force:              false,
		})
	}
}

// publishPatchReport queries the local PatchManager for the current update
// list and publishes a PatchReport on fleet.agent.{id}.patches. Returns the
// reboot_required flag so callers can chain a RebootCommand when policy
// demands it.
func (h *Handler) publishPatchReport(ctx context.Context) (bool, error) {
	if h.pm == nil {
		return false, nil
	}
	updates, reboot, err := h.pm.DetectUpdates(ctx)
	if err != nil {
		slog.Warn("agentpolicy: post-apply detect failed", "err", err)
		return false, err
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
		return reboot, err
	}
	if h.nc != nil {
		_ = h.nc.Publish("fleet.agent."+h.deviceID+".patches", data)
	}
	return reboot, nil
}

// handleRebootCommand processes a RebootCommand.
//   - if cmd.Force=true → skip session check, broadcast, wait grace, reboot.
//   - else check session; if active:
//   - increment defer counter
//   - if counter < maxDefer → publish RebootReport(deferred_user_active) and return
//   - if counter >= maxDefer → force path (log, broadcast, wait, reboot)
//   - else no active session → broadcast, wait grace, reboot.
//
// RebootReport is published only for non-success outcomes
// (deferred_user_active, forced_after_max_defers, error). A successful
// reboot is implicitly confirmed by the next heartbeat after the host
// comes back up — there's no point publishing "rebooted" before since
// the agent's NATS connection vanishes during the reboot anyway, and
// publishing it pre-reboot creates a false-positive record if the
// reboot itself fails.
func (h *Handler) handleRebootCommand(ctx context.Context, cmd *lmdmv1.RebootCommand) {
	grace := time.Duration(cmd.GetGracePeriodSeconds()) * time.Second
	if grace <= 0 {
		grace = 5 * time.Minute
	}
	maxDefer := h.maxDeferCount
	if maxDefer <= 0 {
		maxDefer = 3
	}

	force := cmd.GetForce()
	if !force && h.session != nil && h.session.HasActiveSession(ctx) {
		h.deferReboot(ctx, cmd, maxDefer, grace)
		return
	}

	// Proceed with the reboot.
	if h.rebootExec != nil {
		msg := cmd.GetUserMessage()
		if msg == "" {
			msg = "LMDM: system reboot in progress."
		}
		_ = h.rebootExec.Broadcast(ctx, msg+"\nReboot in "+grace.Round(time.Second).String()+".")
		_ = h.rebootExec.Sleep(ctx, grace)
		if err := h.rebootExec.Reboot(ctx); err != nil {
			slog.Error("agentpolicy: reboot failed", "err", err)
			_ = h.publishRebootReport(ctx, cmd, "error", 0)
			return
		}
	}
	if h.state != nil {
		_ = h.state.ClearRebootDefer()
	}
}

// deferReboot increments the counter and decides between skip or force.
func (h *Handler) deferReboot(ctx context.Context, cmd *lmdmv1.RebootCommand, maxDefer int, grace time.Duration) {
	var state agentstate.RebootDeferState
	if h.state != nil {
		state, _ = h.state.GetRebootDefer()
	}
	state.Count++
	state.LastDeferredAt = time.Now().UTC()

	if state.Count >= maxDefer {
		slog.Warn("agentpolicy: reboot defer limit reached, forcing",
			"count", state.Count, "max", maxDefer)
		_ = h.publishRebootReport(ctx, cmd, "forced_after_max_defers", state.Count)
		if h.rebootExec != nil {
			forceMsg := fmt.Sprintf("LMDM: maintenance reboot in progress (deferred %d times). Please save your work.", state.Count)
			_ = h.rebootExec.Broadcast(ctx, forceMsg)
			_ = h.rebootExec.Sleep(ctx, grace)
			_ = h.rebootExec.Reboot(ctx)
		}
		if h.state != nil {
			_ = h.state.ClearRebootDefer()
		}
		return
	}

	slog.Info("agentpolicy: reboot deferred, user session active",
		"count", state.Count, "max", maxDefer)
	if h.state != nil {
		_ = h.state.SetRebootDefer(state)
	}
	_ = h.publishRebootReport(ctx, cmd, "deferred_user_active", state.Count)
}

// publishRebootReport publishes on status.device.{deviceID}.reboot-report.
// Best-effort: errors are logged, not propagated (the reboot is the point).
func (h *Handler) publishRebootReport(_ context.Context, cmd *lmdmv1.RebootCommand, outcome string, deferCount int) error {
	rep := &lmdmv1.RebootReport{
		DeviceId:    &lmdmv1.DeviceID{Id: h.deviceID},
		AttemptedAt: timestamppb.Now(),
		Outcome:     outcome,
		DeferCount:  int32(deferCount),
		Reason:      cmd.GetReason(),
	}
	data, err := proto.Marshal(rep)
	if err != nil {
		return err
	}
	subject := "status.device." + h.deviceID + ".reboot-report"
	if h.nc == nil {
		return nil
	}
	if err := h.nc.Publish(subject, data); err != nil {
		slog.Warn("agentpolicy: reboot report publish failed", "err", err)
		return err
	}
	return h.nc.Flush()
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
	if h.nc == nil {
		return
	}
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
	TenantID       string
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
		TenantID:       cmd.GetTenantId(),
	}, nil
}
