// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package healthingester subscribes to the JetStream HEALTH stream
// (subject fleet.agent.*.health) and persists each HealthSnapshot into
// the health_snapshots table while updating the denormalized summary
// on devices.
package healthingester

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
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/natsbus"
)

// Ingester subscribes to fleet.agent.*.health and persists snapshots.
type Ingester struct {
	bus      *natsbus.Bus
	devices  *devices.Repository
	consumer jetstream.ConsumeContext
}

// New wires an Ingester.
func New(bus *natsbus.Bus, devicesRepo *devices.Repository) *Ingester {
	return &Ingester{bus: bus, devices: devicesRepo}
}

// Start creates a JetStream consumer and begins processing.
func (i *Ingester) Start(ctx context.Context) error {
	stream, err := i.bus.JetStream().Stream(ctx, "HEALTH")
	if err != nil {
		return fmt.Errorf("healthingester: stream: %w", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "health-ingester",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: "fleet.agent.*.health",
	})
	if err != nil {
		return fmt.Errorf("healthingester: consumer: %w", err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		i.handle(ctx, msg)
	})
	if err != nil {
		return fmt.Errorf("healthingester: consume: %w", err)
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
	var snap lmdmv1.HealthSnapshot
	if err := proto.Unmarshal(msg.Data(), &snap); err != nil {
		slog.Warn("healthingester: bad snapshot", "err", err)
		_ = msg.Term()
		return
	}
	deviceID, err := uuid.Parse(snap.GetDeviceId().GetId())
	if err != nil {
		_ = msg.Term()
		return
	}

	// Resolve tenant from the device row (we don't carry tenant_id on the wire).
	tenantID, err := i.devices.FindTenantForDevice(ctx, deviceID)
	if err != nil {
		if errors.Is(err, devices.ErrNotFound) {
			_ = msg.Term()
			return
		}
		_ = msg.Nak()
		return
	}

	// Marshal the proto to JSON for the JSONB column.
	jsonBytes, err := protojson.Marshal(&snap)
	if err != nil {
		slog.Warn("healthingester: protojson marshal failed", "err", err)
		_ = msg.Term()
		return
	}

	dbScore := healthScoreToDB(snap.OverallScore)
	summary := summarize(&snap)

	if err := i.devices.UpsertHealthSnapshot(ctx, tenantID, deviceID, devices.HealthSummary{
		OverallScore:       dbScore,
		BatteryHealthPct:   summary.batteryPct,
		CriticalDiskCount:  summary.criticalDisks,
		WarningDiskCount:   summary.warningDisks,
		FwupdUpdatesCount:  summary.fwupdUpdates,
		FwupdCriticalCount: summary.fwupdCritical,
	}, jsonBytes); err != nil {
		slog.Warn("healthingester: upsert snapshot", "err", err)
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}

// snapSummary holds the denormalized counters extracted from a snapshot.
type snapSummary struct {
	batteryPct    *int32
	criticalDisks int32
	warningDisks  int32
	fwupdUpdates  int32
	fwupdCritical int32
}

// summarize extracts the indexed/denormalized fields from a HealthSnapshot.
func summarize(s *lmdmv1.HealthSnapshot) snapSummary {
	var sum snapSummary
	if s.Battery != nil && s.Battery.Present {
		v := int32(s.Battery.HealthPct) //nolint:gosec // proto uint32 in [0,100]
		sum.batteryPct = &v
	}
	for _, d := range s.Disks {
		switch d.Score {
		case lmdmv1.HealthScore_HEALTH_SCORE_RED:
			sum.criticalDisks++
		case lmdmv1.HealthScore_HEALTH_SCORE_ORANGE:
			sum.warningDisks++
		}
	}
	for _, f := range s.FirmwareUpdates {
		sum.fwupdUpdates++
		if f.Severity == "critical" {
			sum.fwupdCritical++
		}
	}
	return sum
}

// healthScoreToDB maps the proto enum to the DB SMALLINT column. The
// health_snapshots.overall_score CHECK constraint enforces 0..2, so the
// 4-valued proto enum is collapsed:
//
//	UNSPECIFIED, GREEN -> 0
//	ORANGE             -> 1
//	RED                -> 2
func healthScoreToDB(s lmdmv1.HealthScore) int16 {
	switch s {
	case lmdmv1.HealthScore_HEALTH_SCORE_RED:
		return 2
	case lmdmv1.HealthScore_HEALTH_SCORE_ORANGE:
		return 1
	default:
		return 0
	}
}
