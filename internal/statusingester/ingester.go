// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package statusingester subscribes to the JetStream STATUS stream and
// updates devices.last_seen + agent_version when a Heartbeat arrives.
package statusingester

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/natsbus"
)

// Ingester listens to fleet.agent.*.status and updates the devices table.
type Ingester struct {
	bus      *natsbus.Bus
	devices  *devices.Repository
	consumer jetstream.ConsumeContext
}

// New wires an Ingester.
func New(bus *natsbus.Bus, repo *devices.Repository) *Ingester {
	return &Ingester{bus: bus, devices: repo}
}

// Start creates a JetStream consumer on the STATUS stream and begins
// processing messages in the background. Stop must be called to release
// resources.
func (i *Ingester) Start(ctx context.Context) error {
	stream, err := i.bus.JetStream().Stream(ctx, "STATUS")
	if err != nil {
		return fmt.Errorf("statusingester: stream STATUS: %w", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "status-ingester",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: "fleet.agent.*.status",
	})
	if err != nil {
		return fmt.Errorf("statusingester: consumer: %w", err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		i.handle(ctx, msg)
	})
	if err != nil {
		return fmt.Errorf("statusingester: consume: %w", err)
	}
	i.consumer = cc
	return nil
}

// Stop releases the JetStream consumer.
func (i *Ingester) Stop() {
	if i.consumer != nil {
		i.consumer.Stop()
		i.consumer = nil
	}
}

func (i *Ingester) handle(ctx context.Context, msg jetstream.Msg) {
	var hb lmdmv1.Heartbeat
	if err := proto.Unmarshal(msg.Data(), &hb); err != nil {
		slog.Warn("statusingester: bad heartbeat", "err", err)
		_ = msg.Term()
		return
	}
	deviceID, err := uuid.Parse(hb.GetDeviceId().GetId())
	if err != nil {
		slog.Warn("statusingester: bad device_id", "id", hb.GetDeviceId().GetId(), "err", err)
		_ = msg.Term()
		return
	}

	// Tenant-agnostic update keyed on id alone. RLS bypass is acceptable in
	// the MVP because the server connects as table owner; same pattern as
	// tokens.ValidateAndConsume.
	if err := i.updateByID(ctx, deviceID, &hb); err != nil {
		if errors.Is(err, devices.ErrNotFound) {
			slog.Warn("statusingester: heartbeat for unknown device", "id", deviceID)
			_ = msg.Term()
			return
		}
		slog.Error("statusingester: update failed", "id", deviceID, "err", err)
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}

func (i *Ingester) updateByID(ctx context.Context, id uuid.UUID, hb *lmdmv1.Heartbeat) error {
	const q = `UPDATE devices SET last_seen = $1, agent_version = $2 WHERE id = $3`
	pool := i.devices.Pool()
	ts := hb.GetTimestamp().AsTime()
	ct, err := pool.Exec(ctx, q, ts, hb.GetAgentVersion(), id)
	if err != nil {
		return fmt.Errorf("statusingester: update: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return devices.ErrNotFound
	}
	return nil
}
