// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agentinventoryrunner orchestrates the inventory reporting loop.
// Structurally identical to internal/agentrunner but targets a different
// NATS subject and collects a full InventoryReport on each tick.
package agentinventoryrunner

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/cto-externe/lmdm/internal/agentinventory"
)

// Publisher is the minimal NATS publish surface the runner depends on.
// Satisfied structurally by *agentbus.Bus.
type Publisher interface {
	Publish(subject string, data []byte) error
}

// Runner ticks at `interval`, collects a full inventory snapshot, marshals
// an InventoryReport, and publishes it on
// `fleet.agent.{deviceID}.inventory`.
type Runner struct {
	pub      Publisher
	deviceID string
	interval time.Duration
}

// New wires a Runner.
func New(pub Publisher, deviceID string, interval time.Duration) *Runner {
	return &Runner{pub: pub, deviceID: deviceID, interval: interval}
}

// Run loops until ctx is cancelled. Each tick publishes one full inventory
// report. Returns nil on graceful shutdown.
func (r *Runner) Run(ctx context.Context) error {
	subject := "fleet.agent." + r.deviceID + ".inventory"

	send := func() {
		snap := agentinventory.Collect()
		rep := agentinventory.ToReport(snap, r.deviceID)
		data, err := proto.Marshal(rep)
		if err != nil {
			return
		}
		_ = r.pub.Publish(subject, data)
	}

	if ctx.Err() != nil {
		return nil
	}
	send() // initial send at startup

	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			send()
		}
	}
}
