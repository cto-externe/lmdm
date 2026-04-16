// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package patchingester subscribes to the JetStream INVENTORY stream
// (subject fleet.agent.*.patches) and upserts each PatchReport into the
// device_updates table.
package patchingester

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/natsbus"
)

// Ingester subscribes to fleet.agent.*.patches and persists updates.
type Ingester struct {
	bus      *natsbus.Bus
	pool     *db.Pool
	consumer jetstream.ConsumeContext
}

// New wires an Ingester.
func New(bus *natsbus.Bus, pool *db.Pool) *Ingester {
	return &Ingester{bus: bus, pool: pool}
}

// Start creates a JetStream consumer and begins processing.
func (i *Ingester) Start(ctx context.Context) error {
	stream, err := i.bus.JetStream().Stream(ctx, "INVENTORY")
	if err != nil {
		return fmt.Errorf("patchingester: stream: %w", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "patch-ingester",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: "fleet.agent.*.patches",
	})
	if err != nil {
		return fmt.Errorf("patchingester: consumer: %w", err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		i.handle(ctx, msg)
	})
	if err != nil {
		return fmt.Errorf("patchingester: consume: %w", err)
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
	var report lmdmv1.PatchReport
	if err := proto.Unmarshal(msg.Data(), &report); err != nil {
		slog.Warn("patchingester: bad report", "err", err)
		_ = msg.Term()
		return
	}
	deviceID, err := uuid.Parse(report.GetDeviceId().GetId())
	if err != nil {
		_ = msg.Term()
		return
	}

	// Resolve tenant.
	var tenantID uuid.UUID
	if err := i.pool.QueryRow(ctx, `SELECT tenant_id FROM devices WHERE id = $1`, deviceID).Scan(&tenantID); err != nil {
		if err == pgx.ErrNoRows {
			_ = msg.Term()
			return
		}
		_ = msg.Nak()
		return
	}

	// Replace all updates for this device: DELETE existing + INSERT new.
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		_ = msg.Nak()
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM device_updates WHERE device_id = $1`, deviceID); err != nil {
		slog.Error("patchingester: delete old", "err", err)
		_ = msg.Nak()
		return
	}

	for _, u := range report.GetUpdates() {
		_, err := tx.Exec(ctx,
			`INSERT INTO device_updates (device_id, tenant_id, package_name, current_version, available_version, is_security, source)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			deviceID, tenantID, u.GetName(), u.GetCurrentVersion(), u.GetAvailableVersion(), u.GetSecurity(), u.GetSource(),
		)
		if err != nil {
			slog.Error("patchingester: insert update", "pkg", u.GetName(), "err", err)
			_ = msg.Nak()
			return
		}
	}

	// Update reboot_required on the device.
	if _, err := tx.Exec(ctx, `UPDATE devices SET reboot_required = $1 WHERE id = $2`, report.GetRebootRequired(), deviceID); err != nil {
		slog.Error("patchingester: update reboot", "err", err)
		_ = msg.Nak()
		return
	}

	if err := tx.Commit(ctx); err != nil {
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}
