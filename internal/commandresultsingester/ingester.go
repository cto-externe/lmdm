// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package commandresultsingester subscribes to the JetStream COMMAND_RESULTS
// stream (subject fleet.agent.*.command-result) and forwards each parsed
// CommandResult as a deployments.DeviceResult event into the engine channel.
package commandresultsingester

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/deployments"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/natsbus"
)

// EngineEvents is the subset of deployments.Engine that this ingester needs.
// Scoping the dependency this narrow keeps the ingester independently testable
// with a channel-backed spy.
type EngineEvents interface {
	Events() chan<- deployments.Event
}

// Ingester subscribes to fleet.agent.*.command-result and forwards DeviceResult
// events to the deployments.Engine.
type Ingester struct {
	bus         *natsbus.Bus
	devicesRepo *devices.Repository
	engine      EngineEvents
	consumer    jetstream.ConsumeContext
}

// New wires an Ingester.
func New(bus *natsbus.Bus, devicesRepo *devices.Repository, engine EngineEvents) *Ingester {
	return &Ingester{bus: bus, devicesRepo: devicesRepo, engine: engine}
}

// Start creates a JetStream consumer on the COMMAND_RESULTS stream and begins
// processing. Stop must be called to release the consumer.
func (i *Ingester) Start(ctx context.Context) error {
	stream, err := i.bus.JetStream().Stream(ctx, "COMMAND_RESULTS")
	if err != nil {
		return fmt.Errorf("commandresultsingester: stream: %w", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "command-results-ingester",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: "fleet.agent.*.command-result",
	})
	if err != nil {
		return fmt.Errorf("commandresultsingester: consumer: %w", err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		i.handle(ctx, msg)
	})
	if err != nil {
		return fmt.Errorf("commandresultsingester: consume: %w", err)
	}
	i.consumer = cc
	return nil
}

// Stop releases the consumer.
func (i *Ingester) Stop() {
	if i.consumer != nil {
		i.consumer.Stop()
		i.consumer = nil
	}
}

func (i *Ingester) handle(ctx context.Context, msg jetstream.Msg) {
	var result lmdmv1.CommandResult
	if err := proto.Unmarshal(msg.Data(), &result); err != nil {
		slog.Warn("commandresultsingester: bad result", "err", err)
		_ = msg.Term()
		return
	}
	// Only forward results that carry a deployment_id — results for ad-hoc
	// commands (no deployment) are out of scope for the deployments engine.
	depIDStr := result.GetDeploymentId().GetId()
	if depIDStr == "" {
		_ = msg.Ack()
		return
	}
	depID, err := uuid.Parse(depIDStr)
	if err != nil {
		_ = msg.Term()
		return
	}
	devIDStr := result.GetDeviceId().GetId()
	devID, err := uuid.Parse(devIDStr)
	if err != nil {
		_ = msg.Term()
		return
	}

	// Confirm the device exists (and is known) before forwarding. We don't
	// actually need the tenant here — the Engine resolves tenant via the
	// deployment row — but a Term on unknown devices keeps the queue clean.
	if _, err := i.devicesRepo.FindTenantForDevice(ctx, devID); err != nil {
		if errors.Is(err, devices.ErrNotFound) {
			_ = msg.Term()
			return
		}
		_ = msg.Nak()
		return
	}

	// Marshal the agent's health_checks array into a JSONB-ready byte slice
	// using protojson so the engine/repository can persist it as-is.
	var hcJSON []byte
	if len(result.HealthChecks) > 0 {
		hcJSON = marshalHealthChecks(result.HealthChecks)
	}

	// RolledBack is inferred from the current CommandResult proto shape: the
	// proto has no dedicated flag, but the Task 8 agent handler always rolls
	// back before publishing a failure when it holds a snapshot. Treat any
	// !Success result with a snapshot_id as a rollback. This is a known
	// limitation — revisit if/when a rolled_back bool is added to the proto.
	rolledBack := !result.Success && result.SnapshotId != ""

	select {
	case i.engine.Events() <- deployments.DeviceResult{
		DeploymentID:       depID,
		DeviceID:           devID,
		Success:            result.Success,
		RolledBack:         rolledBack,
		HealthCheckResults: hcJSON,
		ErrorMessage:       result.Error,
		SnapshotID:         result.SnapshotId,
	}:
	case <-ctx.Done():
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}

// marshalHealthChecks serializes []*HealthCheckResult into a JSON array using
// protojson. Returns nil when hcs is empty.
func marshalHealthChecks(hcs []*lmdmv1.HealthCheckResult) []byte {
	if len(hcs) == 0 {
		return nil
	}
	opts := protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: false}
	out := []byte(`[`)
	first := true
	for _, hc := range hcs {
		b, err := opts.Marshal(hc)
		if err != nil {
			continue
		}
		if !first {
			out = append(out, ',')
		}
		out = append(out, b...)
		first = false
	}
	out = append(out, ']')
	return out
}
