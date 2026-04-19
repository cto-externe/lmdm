// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package healthretention periodically deletes old health_snapshots rows so
// the time-series table doesn't grow unbounded. Single-instance assumption
// (matches MVP — see spec §6.5). When the server scales horizontally,
// coordinate via PostgreSQL advisory locks before invoking PruneOnce.
package healthretention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cto-externe/lmdm/internal/db"
)

// DefaultRetention is used when zero is passed to NewPruner.
const DefaultRetention = 90 * 24 * time.Hour

// DefaultInterval is the gap between two prune passes.
const DefaultInterval = 24 * time.Hour

// Pruner deletes health_snapshots older than retention on every tick.
//
// Cross-tenant by design: the table has RLS but the pruner runs as the
// pool owner (server connection) which bypasses RLS for maintenance.
// All retention deletes are tenant-agnostic — the same window applies to
// every tenant in the cluster.
type Pruner struct {
	pool      *db.Pool
	retention time.Duration
	interval  time.Duration
}

// New returns a Pruner with the given retention window. retention <= 0 means
// the default (90 days). interval <= 0 means the default (24h).
func New(pool *db.Pool, retention, interval time.Duration) *Pruner {
	if retention <= 0 {
		retention = DefaultRetention
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Pruner{pool: pool, retention: retention, interval: interval}
}

// Run blocks until ctx is cancelled. First pass is delayed by `interval` so
// startup doesn't fight the ingester for connections — there's no urgency
// on the first day. Returns nil on ctx cancel.
func (p *Pruner) Run(ctx context.Context) error {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if n, err := p.PruneOnce(ctx); err != nil {
				slog.Warn("healthretention: prune failed", "err", err)
			} else if n > 0 {
				slog.Info("healthretention: pruned old snapshots", "deleted", n, "retention_days", p.retention/(24*time.Hour))
			}
		}
	}
}

// PruneOnce deletes rows older than retention. Returns the number of rows
// deleted. Exposed for tests and for an eventual operational CLI.
func (p *Pruner) PruneOnce(ctx context.Context) (int64, error) {
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM health_snapshots
		WHERE ts < NOW() - make_interval(secs => $1)
	`, p.retention.Seconds())
	if err != nil {
		return 0, fmt.Errorf("delete old snapshots: %w", err)
	}
	return tag.RowsAffected(), nil
}
