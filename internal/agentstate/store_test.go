// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentstate

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStore_PendingRoundTrip(t *testing.T) {
	s := newStore(t)
	p := PendingDeployment{
		DeploymentID: "dep-1",
		ProfileID:    "prof-1",
		SnapDir:      "/var/lib/lmdm/snapshots/dep-1",
		StartedAt:    time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC),
	}
	if err := s.SetPending(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPending()
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentID != p.DeploymentID || got.ProfileID != p.ProfileID || got.SnapDir != p.SnapDir {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, p)
	}
	if !got.StartedAt.Equal(p.StartedAt) {
		t.Errorf("StartedAt: got %v, want %v", got.StartedAt, p.StartedAt)
	}
	if err := s.ClearPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPending(); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Clear, expected ErrNotFound, got %v", err)
	}
}

func TestStore_Reopen_PreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := PendingDeployment{DeploymentID: "dep-2", StartedAt: time.Now().UTC().Truncate(time.Second)}
	if err := s1.SetPending(p); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.GetPending()
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentID != "dep-2" {
		t.Errorf("expected dep-2 after reopen, got %q", got.DeploymentID)
	}
}

func TestStore_GetPending_Empty_ReturnsErrNotFound(t *testing.T) {
	s := newStore(t)
	if _, err := s.GetPending(); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on empty store, got %v", err)
	}
}

func TestStore_ClearPending_Idempotent(t *testing.T) {
	s := newStore(t)
	if err := s.ClearPending(); err != nil {
		t.Errorf("clear on empty store should not error, got %v", err)
	}
}

func TestRebootDefer_EmptyByDefault(t *testing.T) {
	s := newStore(t)
	state, err := s.GetRebootDefer()
	if err != nil {
		t.Fatal(err)
	}
	if state.Count != 0 {
		t.Errorf("expected count=0 on empty store, got %d", state.Count)
	}
	if !state.LastDeferredAt.IsZero() {
		t.Errorf("expected zero time on empty store, got %v", state.LastDeferredAt)
	}
}

func TestRebootDefer_SetAndGet(t *testing.T) {
	s := newStore(t)
	ts := time.Date(2026, 4, 22, 9, 0, 0, 0, time.UTC)
	if err := s.SetRebootDefer(RebootDeferState{Count: 2, LastDeferredAt: ts}); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetRebootDefer()
	if err != nil {
		t.Fatal(err)
	}
	if state.Count != 2 {
		t.Errorf("expected count=2, got %d", state.Count)
	}
	if !state.LastDeferredAt.Equal(ts) {
		t.Errorf("expected %v, got %v", ts, state.LastDeferredAt)
	}
}

func TestRebootDefer_Clear_ResetsCounter(t *testing.T) {
	s := newStore(t)
	if err := s.SetRebootDefer(RebootDeferState{Count: 3}); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearRebootDefer(); err != nil {
		t.Fatal(err)
	}
	state, err := s.GetRebootDefer()
	if err != nil {
		t.Fatal(err)
	}
	if state.Count != 0 {
		t.Errorf("expected count=0 after clear, got %d", state.Count)
	}
}

func TestRebootDefer_Persistence_AcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.SetRebootDefer(RebootDeferState{Count: 5}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	state, err := s2.GetRebootDefer()
	if err != nil {
		t.Fatal(err)
	}
	if state.Count != 5 {
		t.Errorf("expected count=5 after reopen, got %d", state.Count)
	}
}
