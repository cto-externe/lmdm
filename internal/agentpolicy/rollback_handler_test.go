// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agentstate"
)

// fakePublisher records every Publish call.
type fakePublisher struct {
	mu    sync.Mutex
	calls []struct {
		subject string
		data    []byte
	}
}

func (p *fakePublisher) Publish(subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	p.calls = append(p.calls, struct {
		subject string
		data    []byte
	}{subject, cp})
	return nil
}

func (p *fakePublisher) last() (string, *lmdmv1.CommandResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return "", nil
	}
	c := p.calls[len(p.calls)-1]
	var r lmdmv1.CommandResult
	_ = proto.Unmarshal(c.data, &r)
	return c.subject, &r
}

func TestRollbackHandler_Handle_EmptyDeploymentID_Fails(t *testing.T) {
	pub := &fakePublisher{}
	h := NewRollbackHandler(pub, nil, t.TempDir(), "dev-1")
	h.Handle(context.Background(), "cmd-1", &lmdmv1.RollbackCommand{})
	subj, res := pub.last()
	if subj != "fleet.agent.dev-1.command-result" {
		t.Errorf("wrong subject: %q", subj)
	}
	if res == nil || res.Success || res.Error == "" {
		t.Errorf("expected failure with non-empty error, got %+v", res)
	}
}

func TestRollbackHandler_Handle_EmptySnapDir_Succeeds(t *testing.T) {
	// policy.Rollback returns nil for an empty snap dir (all 4 sub-rollbacks
	// are no-op when their expected artifacts are missing).
	pub := &fakePublisher{}
	snapRoot := t.TempDir()
	// Create the deployment-id dir but leave it empty.
	if err := os.MkdirAll(filepath.Join(snapRoot, "dep-1"), 0o750); err != nil {
		t.Fatal(err)
	}
	h := NewRollbackHandler(pub, nil, snapRoot, "dev-1")
	h.Handle(context.Background(), "cmd-1", &lmdmv1.RollbackCommand{
		DeploymentId: &lmdmv1.DeploymentID{Id: "dep-1"},
	})
	subj, res := pub.last()
	if subj != "fleet.agent.dev-1.command-result" {
		t.Errorf("wrong subject: %q", subj)
	}
	if res == nil || !res.Success {
		t.Errorf("expected success on empty snap dir, got %+v", res)
	}
	if res.GetDeploymentId().GetId() != "dep-1" {
		t.Errorf("deployment_id not echoed: %v", res.GetDeploymentId())
	}
}

func TestRollbackHandler_Handle_ClearsMatchingPending(t *testing.T) {
	pub := &fakePublisher{}
	storePath := filepath.Join(t.TempDir(), "state.db")
	store, err := agentstate.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetPending(agentstate.PendingDeployment{
		DeploymentID: "dep-1", ProfileID: "prof-1", SnapDir: "/tmp/dep-1", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	snapRoot := t.TempDir()
	_ = os.MkdirAll(filepath.Join(snapRoot, "dep-1"), 0o750)
	h := NewRollbackHandler(pub, store, snapRoot, "dev-1")
	h.Handle(context.Background(), "cmd-1", &lmdmv1.RollbackCommand{
		DeploymentId: &lmdmv1.DeploymentID{Id: "dep-1"},
	})
	if _, err := store.GetPending(); err == nil {
		t.Error("expected pending to be cleared after matching rollback")
	}
}

func TestRollbackHandler_Handle_DoesNotClearUnrelatedPending(t *testing.T) {
	pub := &fakePublisher{}
	storePath := filepath.Join(t.TempDir(), "state.db")
	store, err := agentstate.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetPending(agentstate.PendingDeployment{
		DeploymentID: "dep-OTHER", ProfileID: "prof-1", SnapDir: "/tmp/dep-other", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	snapRoot := t.TempDir()
	_ = os.MkdirAll(filepath.Join(snapRoot, "dep-1"), 0o750)
	h := NewRollbackHandler(pub, store, snapRoot, "dev-1")
	h.Handle(context.Background(), "cmd-1", &lmdmv1.RollbackCommand{
		DeploymentId: &lmdmv1.DeploymentID{Id: "dep-1"},
	})
	p, err := store.GetPending()
	if err != nil {
		t.Fatalf("pending should still be present, got err %v", err)
	}
	if p.DeploymentID != "dep-OTHER" {
		t.Errorf("pending was overwritten")
	}
}
