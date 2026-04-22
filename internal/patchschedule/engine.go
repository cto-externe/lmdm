// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package patchschedule

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// MissedWindowThreshold — schedules whose next_fire_at is older than this
// are skipped, not caught up. Per brainstorm Q6=C: "retry dans les 24h
// sinon skip + marker".
const MissedWindowThreshold = 24 * time.Hour

// CommandPublisher is the minimal NATS surface the engine needs.
type CommandPublisher interface {
	Publish(subject string, data []byte) error
}

// repoIface is the subset of *Repository the engine calls. Exists to allow
// an in-memory fake in engine_test.go without standing up pg testcontainers
// for state-machine coverage.
type repoIface interface {
	FindDue(ctx context.Context, now time.Time) ([]Schedule, error)
	MarkRan(ctx context.Context, id uuid.UUID, ranAt time.Time, status string, nextFire time.Time, skipped bool) error
}

type policyResolver interface {
	Resolve(ctx context.Context, deviceID uuid.UUID) (*ResolvedPolicy, error)
}

// deviceLister enumerates devices for a tenant-wide schedule (device_id NULL).
// One row → one command published per device.
type deviceLister interface {
	ListTenantDeviceIDs(ctx context.Context, tenantID uuid.UUID) ([]uuid.UUID, error)
}

// Engine owns the periodic ticker.
type Engine struct {
	repo      repoIface
	publisher CommandPublisher
	resolver  policyResolver
	devices   deviceLister
	parser    cron.Parser
	interval  time.Duration
	now       func() time.Time
}

// NewEngine wires an Engine. Interval defaults to 60s when 0.
func NewEngine(repo *Repository, pub CommandPublisher, res *Resolver, devs deviceLister, interval time.Duration) *Engine {
	return newEngine(repo, pub, res, devs, interval, time.Now)
}

func newEngine(repo repoIface, pub CommandPublisher, res policyResolver, devs deviceLister, interval time.Duration, nowFn func() time.Time) *Engine {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &Engine{
		repo: repo, publisher: pub, resolver: res, devices: devs,
		// Standard 5-field cron (minute hour dom month dow).
		parser:   cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow),
		interval: interval,
		now:      nowFn,
	}
}

// Run blocks until ctx is canceled, ticking every interval.
func (e *Engine) Run(ctx context.Context) error {
	slog.Info("patchschedule: engine started", "interval", e.interval)
	tk := time.NewTicker(e.interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tk.C:
			if err := e.tick(ctx); err != nil {
				slog.Error("patchschedule: tick failed", "err", err)
			}
		}
	}
}

// tick handles one pass: find due schedules, fire or skip each.
func (e *Engine) tick(ctx context.Context) error {
	now := e.now()
	due, err := e.repo.FindDue(ctx, now)
	if err != nil {
		return err
	}
	for _, s := range due {
		e.fire(ctx, s, now)
	}
	return nil
}

// fire processes one schedule: decide skip vs dispatch, mark ran.
func (e *Engine) fire(ctx context.Context, s Schedule, now time.Time) {
	nextFire, err := e.computeNextFire(s.CronExpr, now)
	if err != nil {
		slog.Error("patchschedule: bad cron_expr, marking error",
			"id", s.ID, "cron", s.CronExpr, "err", err)
		_ = e.repo.MarkRan(ctx, s.ID, now, RunStatusPublishError, now.Add(time.Hour), false)
		return
	}

	// Missed window check — per brainstorm Q6=C: > 24h overdue means skip.
	if now.Sub(s.NextFireAt) > MissedWindowThreshold {
		slog.Warn("patchschedule: missed window, skipping",
			"id", s.ID, "was_due", s.NextFireAt, "overdue", now.Sub(s.NextFireAt))
		_ = e.repo.MarkRan(ctx, s.ID, now, RunStatusSkippedMissedWindow, nextFire, true)
		return
	}

	// Resolve the target device list and publish one command per device.
	targets, err := e.resolveTargets(ctx, s)
	if err != nil {
		slog.Error("patchschedule: resolve targets failed",
			"id", s.ID, "err", err)
		_ = e.repo.MarkRan(ctx, s.ID, now, RunStatusPublishError, nextFire, false)
		return
	}

	for _, devID := range targets {
		if err := e.publishFor(ctx, s, devID); err != nil {
			slog.Error("patchschedule: publish failed",
				"schedule_id", s.ID, "device_id", devID, "err", err)
		}
	}
	_ = e.repo.MarkRan(ctx, s.ID, now, RunStatusOK, nextFire, false)
}

func (e *Engine) computeNextFire(expr string, from time.Time) (time.Time, error) {
	sched, err := e.parser.Parse(expr)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(from), nil
}

func (e *Engine) resolveTargets(ctx context.Context, s Schedule) ([]uuid.UUID, error) {
	if s.DeviceID != nil {
		return []uuid.UUID{*s.DeviceID}, nil
	}
	return e.devices.ListTenantDeviceIDs(ctx, s.TenantID)
}

func (e *Engine) publishFor(ctx context.Context, s Schedule, deviceID uuid.UUID) error {
	policy, err := e.resolver.Resolve(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("resolve policy: %w", err)
	}
	env := &lmdmv1.CommandEnvelope{
		CommandId: "patch-sched-" + s.ID.String() + "-" + deviceID.String(),
		Command: &lmdmv1.CommandEnvelope_ApplyPatches{
			ApplyPatches: &lmdmv1.ApplyPatchesCommand{
				Filter: &lmdmv1.PatchFilter{
					SecurityOnly:    s.FilterSecurityOnly,
					IncludePackages: s.FilterIncludePackages,
					ExcludePackages: s.FilterExcludePackages,
				},
				RebootPolicy: policy.RebootPolicy,
			},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	subject := "fleet.agent." + deviceID.String() + ".commands"
	return e.publisher.Publish(subject, data)
}
