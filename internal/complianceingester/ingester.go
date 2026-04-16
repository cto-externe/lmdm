// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package complianceingester subscribes to the JetStream INVENTORY stream
// (subject fleet.agent.*.compliance) and upserts each ComplianceReport into
// the compliance_reports table.
package complianceingester

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/natsbus"
)

// Ingester subscribes to fleet.agent.*.compliance and persists reports.
type Ingester struct {
	bus      *natsbus.Bus
	pool     *db.Pool
	consumer jetstream.ConsumeContext
}

// New wires an Ingester.
func New(bus *natsbus.Bus, pool *db.Pool) *Ingester {
	return &Ingester{bus: bus, pool: pool}
}

// Start creates a JetStream consumer on the INVENTORY stream and begins
// processing compliance messages in the background.
func (i *Ingester) Start(ctx context.Context) error {
	stream, err := i.bus.JetStream().Stream(ctx, "INVENTORY")
	if err != nil {
		return fmt.Errorf("complianceingester: stream INVENTORY: %w", err)
	}
	cons, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "compliance-ingester",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: "fleet.agent.*.compliance",
	})
	if err != nil {
		return fmt.Errorf("complianceingester: consumer: %w", err)
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		i.handle(ctx, msg)
	})
	if err != nil {
		return fmt.Errorf("complianceingester: consume: %w", err)
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
	var report lmdmv1.ComplianceReport
	if err := proto.Unmarshal(msg.Data(), &report); err != nil {
		slog.Warn("complianceingester: bad report", "err", err)
		_ = msg.Term()
		return
	}
	deviceID, err := uuid.Parse(report.GetDeviceId().GetId())
	if err != nil {
		_ = msg.Term()
		return
	}

	status := "unknown"
	switch report.GetOverallStatus() {
	case lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT:
		status = "compliant"
	case lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT:
		status = "non_compliant"
	}

	var tenantID uuid.UUID
	if err := i.pool.QueryRow(ctx,
		`SELECT tenant_id FROM devices WHERE id = $1`, deviceID,
	).Scan(&tenantID); err != nil {
		if err == pgx.ErrNoRows {
			_ = msg.Term()
			return
		}
		_ = msg.Nak()
		return
	}

	jsonPayload, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(&report)

	const q = `
		INSERT INTO compliance_reports (device_id, tenant_id, overall_status, report_json, received_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (device_id) DO UPDATE
		   SET overall_status = EXCLUDED.overall_status,
		       report_json    = EXCLUDED.report_json,
		       received_at    = EXCLUDED.received_at
	`
	if _, err := i.pool.Exec(ctx, q, deviceID, tenantID, status, jsonPayload); err != nil {
		slog.Error("complianceingester: upsert", "err", err)
		_ = msg.Nak()
		return
	}
	_ = msg.Ack()
}
