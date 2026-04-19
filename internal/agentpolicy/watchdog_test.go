// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cto-externe/lmdm/internal/agentstate"
)

func newTestStore(t *testing.T) *agentstate.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := agentstate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSweepPending_NilStore_NoOp(t *testing.T) {
	if err := SweepPending(context.Background(), nil, 0); err != nil {
		t.Fatalf("expected nil with nil store, got %v", err)
	}
}

func TestSweepPending_NoPending_NoOp(t *testing.T) {
	store := newTestStore(t)
	if err := SweepPending(context.Background(), store, time.Minute); err != nil {
		t.Fatalf("expected nil when no pending row, got %v", err)
	}
}

func TestSweepPending_FreshPending_NoOp(t *testing.T) {
	store := newTestStore(t)
	if err := store.SetPending(agentstate.PendingDeployment{
		DeploymentID: "dep-fresh",
		SnapDir:      t.TempDir(),
		StartedAt:    time.Now().Add(-10 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := SweepPending(context.Background(), store, 5*time.Minute); err != nil {
		t.Fatalf("fresh pending should not be touched, got %v", err)
	}
	// Row should still be present.
	if _, err := store.GetPending(); err != nil {
		t.Errorf("fresh pending should remain, got %v", err)
	}
}

func TestSweepPending_StalePending_RollsBackAndClears(t *testing.T) {
	store := newTestStore(t)
	snapDir := t.TempDir()

	// Seed a sysctl.json so policy.Rollback has something to do without invoking
	// system tools — empty map = noop, which is fine.
	if err := os.WriteFile(filepath.Join(snapDir, "sysctl.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := store.SetPending(agentstate.PendingDeployment{
		DeploymentID: "dep-stale",
		SnapDir:      snapDir,
		StartedAt:    time.Now().Add(-30 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := SweepPending(context.Background(), store, 5*time.Minute); err != nil {
		t.Fatalf("stale rollback failed: %v", err)
	}
	if _, err := store.GetPending(); !errors.Is(err, agentstate.ErrNotFound) {
		t.Errorf("expected pending cleared after sweep, got %v", err)
	}
}

func TestSweepPending_DefaultMaxAgeAppliedWhenZero(t *testing.T) {
	store := newTestStore(t)
	snapDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(snapDir, "sysctl.json"), []byte(`{}`), 0o600)
	if err := store.SetPending(agentstate.PendingDeployment{
		DeploymentID: "dep-default",
		SnapDir:      snapDir,
		StartedAt:    time.Now().Add(-10 * time.Minute), // older than default 5 min
	}); err != nil {
		t.Fatal(err)
	}
	if err := SweepPending(context.Background(), store, 0); err != nil { // 0 → default
		t.Fatalf("sweep with maxAge=0 (default) failed: %v", err)
	}
	if _, err := store.GetPending(); !errors.Is(err, agentstate.ErrNotFound) {
		t.Errorf("expected default max age (5min) to apply, pending should be cleared")
	}
}
