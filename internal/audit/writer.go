// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package audit

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/db"
)

// Writer inserts events into audit_log.
type Writer struct {
	pool *db.Pool
}

// NewWriter returns a Writer backed by pool.
func NewWriter(pool *db.Pool) *Writer { return &Writer{pool: pool} }

// Event is one row to insert. See the audit_log migration (0002) for column semantics.
//
// Actor is a free-form descriptor of the caller. Use one of:
//   - "user:<uuid>" for console actions attributable to a user
//   - "system"     for server-initiated actions (cron, periodic tasks)
//   - "agent:<id>" for agent-initiated actions when relevant
//
// Prefer the builder helpers ActorUser / ActorSystem / ActorAgent below.
type Event struct {
	TenantID     uuid.UUID
	Actor        string
	Action       Action
	ResourceType string         // may be empty
	ResourceID   string         // may be empty
	SourceIP     net.IP         // may be nil
	Details      map[string]any // may be nil
}

// ActorUser formats a user actor string.
func ActorUser(userID uuid.UUID) string { return "user:" + userID.String() }

// ActorSystem is the sentinel for server-initiated events.
const ActorSystem = "system"

// ActorAgent formats an agent actor string.
func ActorAgent(agentID uuid.UUID) string { return "agent:" + agentID.String() }

// Write persists e into audit_log under tenant-scoped RLS.
//
// A nil Writer (or one constructed with a nil pool) is a no-op: audit is a
// nice-to-have observability signal and must never fail a request.
func (w *Writer) Write(ctx context.Context, e Event) error {
	if w == nil || w.pool == nil {
		return nil
	}
	var detailsJSON []byte
	if e.Details != nil {
		b, err := json.Marshal(e.Details)
		if err != nil {
			return err
		}
		detailsJSON = b
	}
	var ipArg any
	if e.SourceIP != nil {
		if a, ok := netip.AddrFromSlice(e.SourceIP.To16()); ok {
			ipArg = a.Unmap()
		}
	}

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, e.TenantID.String()); err != nil {
		return err
	}
	resType := nullableText(e.ResourceType)
	resID := nullableText(e.ResourceID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (tenant_id, actor, action, resource_type, resource_id, source_ip, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
	`, e.TenantID, e.Actor, string(e.Action), resType, resID, ipArg, detailsJSON); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// nullableText returns nil for empty strings so NULL-able columns receive SQL NULL.
func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
