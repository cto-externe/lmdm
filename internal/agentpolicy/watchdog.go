// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cto-externe/lmdm/internal/agentstate"
	"github.com/cto-externe/lmdm/internal/policy"
)

// DefaultMaxPendingAge is the default cutoff used by SweepPending. Pending
// deployments older than this are assumed to belong to a crashed previous
// agent process and get rolled back at startup.
const DefaultMaxPendingAge = 5 * time.Minute

// SweepPending is invoked once at agent startup. It checks the BoltDB store
// for a pending deployment row and, if it's older than maxAge, rolls it back
// using policy.Rollback against its snap dir, then clears the row.
//
// Returns nil on:
//   - no pending row
//   - pending row younger than maxAge (still fresh — let the running Apply finish)
//
// Returns a non-nil error only when the rollback itself failed; the row stays
// in place so the next sweep can retry.
func SweepPending(ctx context.Context, store *agentstate.Store, maxAge time.Duration) error {
	if store == nil {
		return nil
	}
	if maxAge <= 0 {
		maxAge = DefaultMaxPendingAge
	}
	p, err := store.GetPending()
	if errors.Is(err, agentstate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("agentpolicy: read pending: %w", err)
	}
	age := time.Since(p.StartedAt)
	if age < maxAge {
		slog.Info("agentpolicy: pending deployment is fresh, leaving it alone",
			"deployment_id", p.DeploymentID, "age", age, "max_age", maxAge)
		return nil
	}
	slog.Warn("agentpolicy: stale pending deployment, rolling back",
		"deployment_id", p.DeploymentID, "started_at", p.StartedAt, "age", age, "snap_dir", p.SnapDir)
	if err := policy.Rollback(ctx, p.SnapDir); err != nil {
		return fmt.Errorf("agentpolicy: watchdog rollback: %w", err)
	}
	if err := store.ClearPending(); err != nil {
		return fmt.Errorf("agentpolicy: clear pending after rollback: %w", err)
	}
	return nil
}
