// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package inventoryingester subscribes to the JetStream INVENTORY stream
// and upserts each incoming InventoryReport into the device_inventory table.
package inventoryingester

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

// Ingester subscribes to fleet.agent.*.inventory and persists reports.
type Ingester struct {
	bus      *natsbus.Bus
	devices  *devices.Repository
	consumer jetstream.ConsumeContext
}

// New wires an Ingester.
func New(bus *natsbus.Bus, repo *devices.Repository) *Ingester {
	return &Ingester{bus: bus, devices: repo}
}

// Start creates a JetStream consumer on the INVENTORY stream and begins
// processing messages in the background. Stop must be called to release
// resources.
func (i *Ingester) Start(ctx context.Context) error {
	stream, err := i.bus.JetStream().Stream(ctx, "INVENTORY")
	if err != nil {
		return fmt.Errorf("inventoryingester: stream INVENTORY: %w", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "inventory-ingester",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: "fleet.agent.*.inventory",
	})
	if err != nil {
		return fmt.Errorf("inventoryingester: consumer: %w", err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		i.handle(ctx, msg)
	})
	if err != nil {
		return fmt.Errorf("inventoryingester: consume: %w", err)
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
	var rep lmdmv1.InventoryReport
	if err := proto.Unmarshal(msg.Data(), &rep); err != nil {
		slog.Warn("inventoryingester: bad inventory report", "err", err)
		_ = msg.Term()
		return
	}
	deviceID, err := uuid.Parse(rep.GetDeviceId().GetId())
	if err != nil {
		slog.Warn("inventoryingester: bad device_id", "id", rep.GetDeviceId().GetId(), "err", err)
		_ = msg.Term()
		return
	}

	if err := i.upsert(ctx, deviceID, msg.Data(), &rep); err != nil {
		if errors.Is(err, devices.ErrNotFound) {
			slog.Warn("inventoryingester: inventory for unknown device", "id", deviceID)
			_ = msg.Term()
			return
		}
		slog.Error("inventoryingester: upsert failed", "id", deviceID, "err", err)
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}

// upsert renders the report to protojson and UPSERTs one row per device_id.
// Tenant lookup is done via a single DB round-trip: fetch the tenant_id from
// the devices table (which exists because enrollment ran). Same RLS-bypass
// pattern as the status ingester — acceptable at MVP.
func (i *Ingester) upsert(ctx context.Context, id uuid.UUID, raw []byte, rep *lmdmv1.InventoryReport) error {
	pool := i.devices.Pool()

	// Resolve tenant_id from the device row (required by the NOT NULL FK).
	var tenantID uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT tenant_id FROM devices WHERE id = $1`, id,
	).Scan(&tenantID); err != nil {
		return devices.ErrNotFound
	}

	jsonPayload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(rep)
	if err != nil {
		return fmt.Errorf("inventoryingester: protojson: %w", err)
	}

	const q = `
		INSERT INTO device_inventory
		    (device_id, tenant_id, schema_version, is_full, report_bytes, report_json, received_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (device_id) DO UPDATE
		   SET schema_version = EXCLUDED.schema_version,
		       is_full        = EXCLUDED.is_full,
		       report_bytes   = EXCLUDED.report_bytes,
		       report_json    = EXCLUDED.report_json,
		       received_at    = EXCLUDED.received_at
	`
	if _, err := pool.Exec(ctx, q,
		id, tenantID, rep.GetSchemaVersion(), rep.GetIsFull(),
		raw, jsonPayload,
	); err != nil {
		return fmt.Errorf("inventoryingester: upsert: %w", err)
	}
	return nil
}
