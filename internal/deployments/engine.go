// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package deployments

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/profiles"
)

// CommandPublisher is the minimal NATS-bus surface the Engine needs to push
// ApplyProfile / Rollback commands onto fleet.agent.{id}.commands. Taking an
// interface (not *nats.Conn) keeps the Engine testable with an in-memory fake.
type CommandPublisher interface {
	Publish(subject string, data []byte) error
}

// ProfileLoader is the subset of profiles.Repository the Engine depends on.
// Same motivation as CommandPublisher: lets tests substitute a fake without
// standing up the full profile store.
type ProfileLoader interface {
	FindByID(ctx context.Context, tenantID, id uuid.UUID) (*profiles.Profile, error)
}

// repoIface is the subset of *Repository the Engine calls. It exists so
// engine_test.go can swap in an in-memory fake — the alternative (sharing a
// real Postgres in unit tests) is too slow for the state-machine coverage we
// want here. Keep this list tight; adding methods means fake test setup grows.
type repoIface interface {
	Create(ctx context.Context, tenantID uuid.UUID, in Deployment) (*Deployment, error)
	FindByID(ctx context.Context, tenantID, id uuid.UUID) (*Deployment, error)
	FindTenantForDeployment(ctx context.Context, id uuid.UUID) (uuid.UUID, error)
	UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, s Status, reason string) error
	SetCanaryStarted(ctx context.Context, tenantID, id uuid.UUID) error
	SetCanaryFinished(ctx context.Context, tenantID, id uuid.UUID) error
	SetValidated(ctx context.Context, tenantID, id uuid.UUID) error
	SetCompleted(ctx context.Context, tenantID, id uuid.UUID) error
	UpsertResult(ctx context.Context, tenantID, depID, devID uuid.UUID, in Result) error
	ListResults(ctx context.Context, tenantID, depID uuid.UUID) ([]Result, error)
}

// Engine drives the deployment state machine. All transitions happen inside
// the goroutine started by Run() in response to events posted on Events() —
// external producers (REST handlers, COMMAND_RESULTS consumer, validation
// timer) never mutate state directly, which removes the need for locking
// around the transition logic itself. The sync.Mutex guards only the timer
// map, which is touched from both the goroutine and time.AfterFunc callbacks.
type Engine struct {
	repo     repoIface
	bus      CommandPublisher
	profiles ProfileLoader
	events   chan Event

	mu     sync.Mutex
	timers map[uuid.UUID]*time.Timer // one validation-timeout timer per deployment in semi_auto
}

// NewEngine wires an Engine. Callers must call Run(ctx) in a goroutine before
// posting events; Create() itself doesn't need the goroutine running because
// the synchronous canary push is handled on the calling goroutine.
func NewEngine(repo *Repository, bus CommandPublisher, profs ProfileLoader) *Engine {
	return newEngineWithRepo(repo, bus, profs)
}

// newEngineWithRepo is the test hook that accepts the interface directly.
// Production code goes through NewEngine which feeds in *Repository.
func newEngineWithRepo(repo repoIface, bus CommandPublisher, profs ProfileLoader) *Engine {
	return &Engine{
		repo:     repo,
		bus:      bus,
		profiles: profs,
		events:   make(chan Event, 128),
		timers:   make(map[uuid.UUID]*time.Timer),
	}
}

// Events returns the write-only channel event producers post to. The channel
// is buffered so bursts from the bus consumer don't block; if it ever fills
// up that's a signal the Engine goroutine is stuck and the operator should
// investigate rather than have us silently drop events.
func (e *Engine) Events() chan<- Event { return e.events }

// Run blocks until ctx is cancelled, handling events as they arrive. Pending
// validation timers are stopped on shutdown; if they fire after Stop(), the
// channel send inside the AfterFunc closure is discarded because the receive
// loop has exited and the Go runtime will GC the buffered event.
func (e *Engine) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			e.stopAllTimers()
			return nil
		case ev := <-e.events:
			e.handle(ctx, ev)
		}
	}
}

// DeploymentSpec is the input shape for Create(); it mirrors the fields the
// REST layer receives and then passes through. Keeping this as a DTO (rather
// than Deployment itself) separates user-supplied fields from server-managed
// ones (status, timestamps, reason).
type DeploymentSpec struct {
	TenantID                 uuid.UUID
	ProfileID                uuid.UUID
	TargetDeviceIDs          []uuid.UUID
	CanaryDeviceID           uuid.UUID
	ValidationMode           ValidationMode
	ValidationTimeoutSeconds int
	FailureThresholdPct      int
	CreatedByUserID          *uuid.UUID
}

// Create persists a new deployment and immediately pushes the canary
// ApplyProfileCommand, transitioning the row to canary_running. If the
// canary push fails synchronously (e.g., NATS is down), the deployment is
// flipped to canary_failed before returning; the caller gets a non-nil
// Deployment so it can surface the reason via the REST response.
func (e *Engine) Create(ctx context.Context, spec DeploymentSpec) (*Deployment, error) {
	if spec.CanaryDeviceID == uuid.Nil {
		return nil, errors.New("canary_device_id required")
	}
	if len(spec.TargetDeviceIDs) == 0 {
		return nil, errors.New("target_device_ids required")
	}
	if !spec.ValidationMode.IsValid() {
		spec.ValidationMode = ModeManual
	}
	if spec.ValidationTimeoutSeconds <= 0 {
		spec.ValidationTimeoutSeconds = 1800
	}
	if spec.FailureThresholdPct <= 0 || spec.FailureThresholdPct > 100 {
		spec.FailureThresholdPct = 10
	}

	// The canary must be part of the target set — otherwise the rollout phase
	// would push to a strict superset of devices, which confuses both auditing
	// and abort-threshold math.
	canaryFound := false
	for _, d := range spec.TargetDeviceIDs {
		if d == spec.CanaryDeviceID {
			canaryFound = true
			break
		}
	}
	if !canaryFound {
		return nil, errors.New("canary_device_id must be included in target_device_ids")
	}

	d := Deployment{
		TenantID:                 spec.TenantID,
		ProfileID:                spec.ProfileID,
		TargetDeviceIDs:          spec.TargetDeviceIDs,
		CanaryDeviceID:           spec.CanaryDeviceID,
		Status:                   StatusPlanned,
		ValidationMode:           spec.ValidationMode,
		ValidationTimeoutSeconds: spec.ValidationTimeoutSeconds,
		FailureThresholdPct:      spec.FailureThresholdPct,
		CreatedByUserID:          spec.CreatedByUserID,
	}
	created, err := e.repo.Create(ctx, spec.TenantID, d)
	if err != nil {
		return nil, err
	}

	// Push the canary command synchronously so the REST caller sees failures
	// immediately instead of having to poll. A successful publish only means
	// NATS accepted the message — the agent's result arrives asynchronously
	// via the COMMAND_RESULTS consumer and drives the next transition.
	if err := e.pushApplyCommand(ctx, created, created.CanaryDeviceID, true); err != nil {
		reason := "canary push failed: " + err.Error()
		_ = e.repo.UpdateStatus(ctx, spec.TenantID, created.ID, StatusCanaryFailed, reason)
		created.Status = StatusCanaryFailed
		created.Reason = reason
		return created, nil
	}
	_ = e.repo.UpsertResult(ctx, spec.TenantID, created.ID, created.CanaryDeviceID, Result{
		TenantID: spec.TenantID, DeploymentID: created.ID, DeviceID: created.CanaryDeviceID,
		IsCanary: true, Status: ResultApplying,
	})
	_ = e.repo.SetCanaryStarted(ctx, spec.TenantID, created.ID)
	_ = e.repo.UpdateStatus(ctx, spec.TenantID, created.ID, StatusCanaryRunning, "")
	created.Status = StatusCanaryRunning
	return created, nil
}

// handle dispatches one event. Every handler is idempotent: re-delivery on a
// terminal state is a no-op with a WARN log rather than an error, because
// JetStream at-least-once semantics guarantee we'll see duplicates.
func (e *Engine) handle(ctx context.Context, ev Event) {
	switch v := ev.(type) {
	case DeviceResult:
		e.onDeviceResult(ctx, v)
	case Validate:
		e.onValidate(ctx, v)
	case Rollback:
		e.onRollback(ctx, v)
	case ValidationTimeout:
		e.onValidationTimeout(ctx, v)
	default:
		slog.Warn("deployments: unknown event type", "type", fmt.Sprintf("%T", ev))
	}
}

// onDeviceResult handles the canary result and per-device rollout results.
// Canary success transitions to awaiting_validation (manual/semi_auto) or
// straight to rolling_out (auto); rollout results accumulate until the
// deployment either completes, partially-fails, or trips the abort threshold.
func (e *Engine) onDeviceResult(ctx context.Context, ev DeviceResult) {
	d, err := e.findByID(ctx, ev.DeploymentID)
	if err != nil {
		slog.Warn("deployments: device result for unknown deployment",
			"deployment_id", ev.DeploymentID, "err", err)
		return
	}
	if d.Status.IsTerminal() {
		slog.Info("deployments: ignoring device result in terminal state",
			"deployment_id", d.ID, "status", d.Status)
		return
	}

	// Record the per-device result. We map the agent's boolean success/
	// rolled_back into one of the three non-trivial result statuses.
	resultStatus := ResultSuccess
	if !ev.Success {
		if ev.RolledBack {
			resultStatus = ResultRolledBack
		} else {
			resultStatus = ResultFailed
		}
	}
	_ = e.repo.UpsertResult(ctx, d.TenantID, d.ID, ev.DeviceID, Result{
		TenantID:           d.TenantID,
		DeploymentID:       d.ID,
		DeviceID:           ev.DeviceID,
		IsCanary:           ev.DeviceID == d.CanaryDeviceID,
		Status:             resultStatus,
		SnapshotID:         ev.SnapshotID,
		HealthCheckResults: ev.HealthCheckResults,
		ErrorMessage:       ev.ErrorMessage,
	})

	isCanary := ev.DeviceID == d.CanaryDeviceID
	if isCanary && d.Status == StatusCanaryRunning {
		if !ev.Success {
			// Canary failure short-circuits everything: we never push to the
			// rollout targets. The deployment lands in rolled_back so the
			// REST GET /deployments/{id} shows a terminal status.
			_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusCanaryFailed, "canary failed: "+ev.ErrorMessage)
			_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusRolledBack, "")
			return
		}
		_ = e.repo.SetCanaryFinished(ctx, d.TenantID, d.ID)
		_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusCanaryOK, "")
		// Advance per validation mode:
		//   auto      → push the rollout and flip to rolling_out immediately
		//   semi_auto → wait in awaiting_validation; arm timer to auto-validate
		//   manual    → wait in awaiting_validation indefinitely
		switch d.ValidationMode {
		case ModeAuto:
			_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusRollingOut, "")
			e.pushRollout(ctx, d)
		case ModeSemiAuto:
			_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusAwaitingValidation, "")
			e.armValidationTimer(d.ID, time.Duration(d.ValidationTimeoutSeconds)*time.Second)
		default:
			_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusAwaitingValidation, "")
		}
		return
	}

	// Non-canary results during rolling_out — re-evaluate completion + abort.
	if d.Status == StatusRollingOut {
		e.checkRolloutProgress(ctx, d)
	}
}

// onValidate is the handler for POST /deployments/{id}/validate. It only
// takes effect while the deployment is still AWAITING_VALIDATION; every
// other status is a no-op with a warning, because re-validating a finished
// or running rollout would desync the canary_finished_at / validated_at
// timestamps.
func (e *Engine) onValidate(ctx context.Context, ev Validate) {
	d, err := e.findByID(ctx, ev.DeploymentID)
	if err != nil {
		return
	}
	if d.Status != StatusAwaitingValidation {
		slog.Warn("deployments: validate in wrong state", "deployment_id", d.ID, "status", d.Status)
		return
	}
	e.cancelValidationTimer(d.ID)
	_ = e.repo.SetValidated(ctx, d.TenantID, d.ID)
	_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusRollingOut, "")
	e.pushRollout(ctx, d)
}

// onRollback handles POST /deployments/{id}/rollback: push a RollbackCommand
// to every device that recorded a success or still-applying result, then
// transition the deployment to the ROLLED_BACK terminal state. Failed or
// already-rolled-back devices are skipped — there's nothing to undo there
// because the agent either never applied the change or already reverted it.
func (e *Engine) onRollback(ctx context.Context, ev Rollback) {
	d, err := e.findByID(ctx, ev.DeploymentID)
	if err != nil {
		return
	}
	if d.Status.IsTerminal() {
		return
	}
	e.cancelValidationTimer(d.ID)

	results, err := e.repo.ListResults(ctx, d.TenantID, d.ID)
	if err != nil {
		slog.Warn("deployments: list results during rollback failed", "deployment_id", d.ID, "err", err)
		return
	}
	for _, r := range results {
		if r.Status == ResultSuccess || r.Status == ResultApplying {
			if err := e.pushRollbackCommand(ctx, d, r.DeviceID); err != nil {
				slog.Warn("deployments: push rollback failed", "device_id", r.DeviceID, "err", err)
			}
		}
	}
	_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusRolledBack, ev.Reason)
}

// onValidationTimeout fires from time.AfterFunc in semi_auto mode. If the
// operator hasn't validated (or rolled back) by the time the timer expires
// and we're still in AWAITING_VALIDATION, we auto-validate on their behalf.
// If the state has moved on (e.g., an operator rolled back), the timer's
// work has already been pre-empted and we no-op.
func (e *Engine) onValidationTimeout(ctx context.Context, ev ValidationTimeout) {
	d, err := e.findByID(ctx, ev.DeploymentID)
	if err != nil {
		return
	}
	if d.Status != StatusAwaitingValidation {
		return
	}
	slog.Info("deployments: validation timer fired, auto-validating", "deployment_id", d.ID)
	_ = e.repo.SetValidated(ctx, d.TenantID, d.ID)
	_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusRollingOut, "auto-validated by timer")
	e.pushRollout(ctx, d)
}

// pushRollout publishes an ApplyProfileCommand to every target except the
// canary (which already got it during Create). A per-target publish error is
// recorded as a failed result for that device and counted toward the abort
// threshold; we don't halt the rollout on a single publish error because the
// remaining devices may still succeed.
func (e *Engine) pushRollout(ctx context.Context, d *Deployment) {
	for _, id := range d.TargetDeviceIDs {
		if id == d.CanaryDeviceID {
			continue
		}
		if err := e.pushApplyCommand(ctx, d, id, false); err != nil {
			slog.Warn("deployments: push apply failed", "device_id", id, "err", err)
			_ = e.repo.UpsertResult(ctx, d.TenantID, d.ID, id, Result{
				TenantID:     d.TenantID,
				DeploymentID: d.ID,
				DeviceID:     id,
				Status:       ResultFailed,
				ErrorMessage: "push failed: " + err.Error(),
			})
			continue
		}
		_ = e.repo.UpsertResult(ctx, d.TenantID, d.ID, id, Result{
			TenantID:     d.TenantID,
			DeploymentID: d.ID,
			DeviceID:     id,
			Status:       ResultApplying,
		})
	}
	// One rolling_out → terminal transition is already driven from
	// onDeviceResult. But if every push failed synchronously, we need to
	// re-check progress here so we don't hang forever waiting for results
	// that will never arrive.
	e.checkRolloutProgress(ctx, d)
}

// checkRolloutProgress transitions to COMPLETED or PARTIALLY_FAILED when all
// rollout targets have reported, or aborts early if the abort threshold is
// hit before completion. Failed and rolled-back per-device results both count
// toward "failed" — from the operator's perspective, both mean "this device
// did not successfully land on the new profile".
func (e *Engine) checkRolloutProgress(ctx context.Context, d *Deployment) {
	results, err := e.repo.ListResults(ctx, d.TenantID, d.ID)
	if err != nil {
		return
	}

	total := len(d.TargetDeviceIDs)
	finished := 0
	failed := 0
	for _, r := range results {
		// Canary's own result is in the rollout phase accounting too, because
		// from the user's standpoint total targets includes the canary device.
		switch r.Status {
		case ResultSuccess, ResultFailed, ResultRolledBack:
			finished++
			if r.Status == ResultFailed || r.Status == ResultRolledBack {
				failed++
			}
		}
	}

	failedPct := 0
	if total > 0 {
		failedPct = failed * 100 / total
	}
	// Abort threshold fires while the rollout is still in flight.
	if failedPct >= d.FailureThresholdPct && finished < total {
		_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusPartiallyFailed,
			fmt.Sprintf("abort threshold hit: %d%% failed", failedPct))
		return
	}

	if finished == total {
		if failed == 0 {
			_ = e.repo.SetCompleted(ctx, d.TenantID, d.ID)
			_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusCompleted, "")
		} else {
			_ = e.repo.UpdateStatus(ctx, d.TenantID, d.ID, StatusPartiallyFailed,
				fmt.Sprintf("%d/%d devices failed", failed, total))
		}
	}
}

// pushApplyCommand publishes an ApplyProfileCommand envelope on
// fleet.agent.{id}.commands. The profile is loaded fresh from storage every
// time so that an edit between canary and rollout is reflected in the
// command stream (the version field distinguishes them).
func (e *Engine) pushApplyCommand(ctx context.Context, d *Deployment, deviceID uuid.UUID, isCanary bool) error {
	prof, err := e.profiles.FindByID(ctx, d.TenantID, d.ProfileID)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}
	env := &lmdmv1.CommandEnvelope{
		CommandId:    uuid.NewString(),
		DeploymentId: &lmdmv1.DeploymentID{Id: d.ID.String()},
		IsCanary:     isCanary,
		Command: &lmdmv1.CommandEnvelope_ApplyProfile{
			ApplyProfile: &lmdmv1.ApplyProfileCommand{
				ProfileId:      &lmdmv1.ProfileID{Id: d.ProfileID.String()},
				Version:        prof.Version,
				ProfileContent: []byte(prof.YAMLContent),
				ProfileSignature: &lmdmv1.HybridSignature{
					Ed25519: prof.SignatureEd25519,
					MlDsa:   prof.SignatureMLDSA,
				},
				TenantId: d.TenantID.String(),
			},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	subject := "fleet.agent." + deviceID.String() + ".commands"
	return e.bus.Publish(subject, data)
}

// pushRollbackCommand publishes a RollbackCommand envelope. The payload is
// minimal: the deployment id tells the agent which snapshot to revert to,
// and the agent's local state already knows the before-state.
func (e *Engine) pushRollbackCommand(_ context.Context, d *Deployment, deviceID uuid.UUID) error {
	env := &lmdmv1.CommandEnvelope{
		CommandId:    uuid.NewString(),
		DeploymentId: &lmdmv1.DeploymentID{Id: d.ID.String()},
		Command: &lmdmv1.CommandEnvelope_Rollback{
			Rollback: &lmdmv1.RollbackCommand{
				DeploymentId: &lmdmv1.DeploymentID{Id: d.ID.String()},
			},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal rollback envelope: %w", err)
	}
	subject := "fleet.agent." + deviceID.String() + ".commands"
	return e.bus.Publish(subject, data)
}

// armValidationTimer installs (or replaces) a time.AfterFunc that posts a
// ValidationTimeout event when d expires. Called under engine goroutine but
// the callback posts to the events channel which is safe from any goroutine.
func (e *Engine) armValidationTimer(id uuid.UUID, d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if existing, ok := e.timers[id]; ok {
		existing.Stop()
	}
	e.timers[id] = time.AfterFunc(d, func() {
		// Best-effort — if the engine has shut down the receive end is gone
		// and the send would block; guard with a non-blocking select so the
		// timer goroutine doesn't leak.
		select {
		case e.events <- ValidationTimeout{DeploymentID: id}:
		default:
		}
	})
}

// cancelValidationTimer stops the pending timer for id, if any. Used when an
// operator validates or rolls back before the timer fires, and on shutdown.
func (e *Engine) cancelValidationTimer(id uuid.UUID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t, ok := e.timers[id]; ok {
		t.Stop()
		delete(e.timers, id)
	}
}

func (e *Engine) stopAllTimers() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, t := range e.timers {
		t.Stop()
		delete(e.timers, id)
	}
}

// findByID looks up a deployment without the caller needing to know the
// tenant. It resolves tenant from the deployment id first, then does the
// RLS-scoped read.
func (e *Engine) findByID(ctx context.Context, id uuid.UUID) (*Deployment, error) {
	tenantID, err := e.repo.FindTenantForDeployment(ctx, id)
	if err != nil {
		return nil, err
	}
	return e.repo.FindByID(ctx, tenantID, id)
}
