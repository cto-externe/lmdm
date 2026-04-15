// Package agentrunner orchestrates the heartbeat loop: collect snapshot →
// build Heartbeat proto → publish on NATS subject. The Publisher interface
// is small enough to mock in unit tests; the production wiring uses
// internal/agentbus.Bus.
package agentrunner

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/cto-externe/lmdm/internal/agentstatus"
)

// Publisher is the minimal NATS publish surface the runner depends on.
// Satisfied structurally by *agentbus.Bus.
type Publisher interface {
	Publish(subject string, data []byte) error
}

// Runner ticks at `interval`, collects a status snapshot, marshals a
// Heartbeat proto, and publishes it on `fleet.agent.{deviceID}.status`.
type Runner struct {
	pub          Publisher
	deviceID     string
	agentVersion string
	interval     time.Duration
}

// New wires a Runner.
func New(pub Publisher, deviceID, agentVersion string, interval time.Duration) *Runner {
	return &Runner{
		pub:          pub,
		deviceID:     deviceID,
		agentVersion: agentVersion,
		interval:     interval,
	}
}

// Run loops until ctx is cancelled. Each tick collects a snapshot and
// publishes a heartbeat. Returns nil on graceful shutdown.
func (r *Runner) Run(ctx context.Context) error {
	subject := "fleet.agent." + r.deviceID + ".status"

	send := func() {
		s, err := agentstatus.Collect()
		if err != nil {
			// Don't kill the loop on a transient collector error; the next
			// tick will retry.
			return
		}
		hb := agentstatus.ToHeartbeat(s, r.deviceID, r.agentVersion)
		data, err := proto.Marshal(hb)
		if err != nil {
			return
		}
		_ = r.pub.Publish(subject, data)
	}

	if ctx.Err() != nil {
		return nil
	}
	send() // initial heartbeat at startup

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
