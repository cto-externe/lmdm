// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agenthealthrunner periodically calls a HealthCollector and publishes
// the resulting HealthSnapshot on NATS. Mirror of agentpatchrunner.
package agenthealthrunner

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// HealthCollector is the minimal interface the runner needs from the
// internal/agenthealth package — keeps this runner free of any sysfs / exec
// concerns and lets tests inject a deterministic snapshot factory.
type HealthCollector interface {
	Collect(ctx context.Context, deviceID string) *lmdmv1.HealthSnapshot
}

// Publisher is the minimal NATS publish surface (matches agentpatchrunner.Publisher
// and agentbus.Bus).
type Publisher interface {
	Publish(subject string, data []byte) error
}

// Runner ticks at `interval`, calls HealthCollector.Collect, marshals a
// HealthSnapshot, and publishes it on `fleet.agent.{deviceID}.health`.
// Default interval per spec §8.2 is 6h.
type Runner struct {
	pub       Publisher
	collector HealthCollector
	deviceID  string
	interval  time.Duration
}

// New wires a Runner. The caller is responsible for ensuring the publisher's
// underlying NATS connection is alive.
func New(pub Publisher, c HealthCollector, deviceID string, interval time.Duration) *Runner {
	return &Runner{pub: pub, collector: c, deviceID: deviceID, interval: interval}
}

// Run loops until ctx is cancelled. Performs an immediate publish on entry so
// the server has data without waiting r.interval.
func (r *Runner) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	r.publishOnce(ctx)

	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.publishOnce(ctx)
		}
	}
}

func (r *Runner) publishOnce(ctx context.Context) {
	snap := r.collector.Collect(ctx, r.deviceID)
	data, err := proto.Marshal(snap)
	if err != nil {
		slog.Error("agenthealthrunner: marshal failed", "err", err)
		return
	}
	subject := "fleet.agent." + r.deviceID + ".health"
	if err := r.pub.Publish(subject, data); err != nil {
		slog.Warn("agenthealthrunner: publish failed", "subject", subject, "err", err)
		return
	}
	slog.Debug("agenthealthrunner: published health snapshot", "subject", subject, "bytes", len(data))
}
