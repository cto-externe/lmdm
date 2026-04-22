// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package rebootingester subscribes to status.device.*.reboot-report and
// updates the devices table + writes an audit event per report.
package rebootingester

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
)

// Subject is the NATS wildcard the ingester subscribes to.
const Subject = "status.device.*.reboot-report"

// Ingester consumes RebootReport messages and updates the devices table.
type Ingester struct {
	nc      *nats.Conn
	pool    *db.Pool
	devices *devices.Repository
	audit   *audit.Writer
	sub     *nats.Subscription
}

// New wires an Ingester. audit.Writer may be nil (audit writes become no-ops).
func New(nc *nats.Conn, pool *db.Pool, devRepo *devices.Repository, aw *audit.Writer) *Ingester {
	return &Ingester{nc: nc, pool: pool, devices: devRepo, audit: aw}
}

// Start subscribes; returns once the subscription is established. The handler
// runs in goroutines managed by nats.go.
func (i *Ingester) Start(ctx context.Context) error {
	sub, err := i.nc.Subscribe(Subject, func(m *nats.Msg) {
		i.handle(ctx, m)
	})
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", Subject, err)
	}
	i.sub = sub
	slog.Info("rebootingester: started", "subject", Subject)
	return nil
}

// Stop unsubscribes.
func (i *Ingester) Stop() error {
	if i.sub != nil {
		return i.sub.Unsubscribe()
	}
	return nil
}

func (i *Ingester) handle(ctx context.Context, m *nats.Msg) {
	var rep lmdmv1.RebootReport
	if err := proto.Unmarshal(m.Data, &rep); err != nil {
		slog.Warn("rebootingester: unmarshal failed", "err", err)
		return
	}
	deviceIDStr := rep.GetDeviceId().GetId()
	deviceID, err := uuid.Parse(deviceIDStr)
	if err != nil {
		slog.Warn("rebootingester: invalid device_id", "id", deviceIDStr)
		return
	}
	outcome := rep.GetOutcome()
	deferCount := int(rep.GetDeferCount())

	// Update devices row based on outcome.
	if err := i.apply(ctx, deviceID, outcome, deferCount); err != nil {
		slog.Error("rebootingester: apply failed", "device", deviceID, "err", err)
		return
	}

	// Audit event.
	if i.audit != nil {
		tenantID, terr := i.devices.FindTenantForDevice(ctx, deviceID)
		if terr == nil {
			success := outcome == "rebooted" || outcome == "forced_after_max_defers"
			_ = i.audit.Write(ctx, audit.Event{
				TenantID:     tenantID,
				Actor:        audit.ActorSystem,
				Action:       audit.ActionDeviceReboot,
				ResourceType: "device",
				ResourceID:   deviceID.String(),
				Details: map[string]any{
					"outcome":     outcome,
					"defer_count": deferCount,
					"reason":      rep.GetReason(),
					"success":     success,
				},
			})
		}
	}
}

// apply writes the right UPDATE per outcome.
//   - rebooted / forced_after_max_defers → clear counters + clear reboot_required
//   - deferred_user_active               → store defer_count + timestamp
//   - other (error / refused / deferred_skipped) → leave state, just log
func (i *Ingester) apply(ctx context.Context, deviceID uuid.UUID, outcome string, deferCount int) error {
	switch outcome {
	case "rebooted", "forced_after_max_defers":
		_, err := i.pool.Exec(ctx, `
			UPDATE devices
			   SET reboot_required = FALSE,
			       pending_reboot_defer_count = 0,
			       pending_reboot_last_deferred_at = NULL
			 WHERE id = $1
		`, deviceID)
		return err
	case "deferred_user_active":
		_, err := i.pool.Exec(ctx, `
			UPDATE devices
			   SET pending_reboot_defer_count = $2,
			       pending_reboot_last_deferred_at = NOW()
			 WHERE id = $1
		`, deviceID, deferCount)
		return err
	default:
		slog.Info("rebootingester: non-state-changing outcome", "outcome", outcome, "device", deviceID)
		return nil
	}
}
