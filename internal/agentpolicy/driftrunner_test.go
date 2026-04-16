// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/policy"
)

type capturingConn struct {
	mu   sync.Mutex
	msgs []publishedMsg
}

type publishedMsg struct {
	subject string
	data    []byte
}

func (c *capturingConn) Publish(subject string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	c.msgs = append(c.msgs, publishedMsg{subject: subject, data: cp})
	return nil
}

func (c *capturingConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func (c *capturingConn) first() publishedMsg {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.msgs) == 0 {
		return publishedMsg{}
	}
	return c.msgs[0]
}

func TestDriftRunnerPublishesComplianceForEmptyProfile(t *testing.T) {
	store := NewProfileStore(t.TempDir())
	// Save an empty profile (no actions → always compliant).
	_ = store.Save("prof-1", []byte("kind: profile\nmetadata:\n  name: test\npolicies: []\n"))

	pub := &capturingConn{}
	runner := NewDriftRunner(pub, policy.DefaultRegistry(), store, "device-drift", 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = runner.Run(ctx)

	if pub.count() < 2 {
		t.Fatalf("got %d compliance reports, want >= 2", pub.count())
	}

	first := pub.first()
	if first.subject != "fleet.agent.device-drift.compliance" {
		t.Errorf("subject = %q", first.subject)
	}
	var report lmdmv1.ComplianceReport
	if err := proto.Unmarshal(first.data, &report); err != nil {
		t.Fatal(err)
	}
	if report.GetOverallStatus() != lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT {
		t.Errorf("status = %v, want COMPLIANT", report.GetOverallStatus())
	}
}

func TestDriftRunnerNoProfilesIsCompliant(t *testing.T) {
	store := NewProfileStore(t.TempDir()) // empty store
	pub := &capturingConn{}
	runner := NewDriftRunner(pub, policy.DefaultRegistry(), store, "device-empty", 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	_ = runner.Run(ctx)

	if pub.count() < 1 {
		t.Fatal("must publish at least one report even with no profiles")
	}
	var report lmdmv1.ComplianceReport
	_ = proto.Unmarshal(pub.first().data, &report)
	if report.GetOverallStatus() != lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT {
		t.Errorf("empty store → should be COMPLIANT, got %v", report.GetOverallStatus())
	}
}

func TestDriftRunnerStopsOnCancel(t *testing.T) {
	store := NewProfileStore(t.TempDir())
	pub := &capturingConn{}
	runner := NewDriftRunner(pub, policy.DefaultRegistry(), store, "x", 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("must return nil on cancel, got %v", err)
	}
}
