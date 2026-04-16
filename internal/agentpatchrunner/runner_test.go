// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpatchrunner

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/distro"
)

type capturingPublisher struct {
	mu   sync.Mutex
	msgs []captured
}

type captured struct {
	subject string
	data    []byte
}

func (p *capturingPublisher) Publish(subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	p.msgs = append(p.msgs, captured{subject: subject, data: cp})
	return nil
}

func (p *capturingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.msgs)
}

func (p *capturingPublisher) first() captured {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.msgs) == 0 {
		return captured{}
	}
	return p.msgs[0]
}

// mockPatchManager returns a fixed update list without running apt/dnf.
type mockPatchManager struct {
	updates []distro.Update
	reboot  bool
}

func (m *mockPatchManager) Family() string                         { return "mock" }
func (m *mockPatchManager) RefreshSources(_ context.Context) error { return nil }
func (m *mockPatchManager) DetectUpdates(_ context.Context) ([]distro.Update, bool, error) {
	return m.updates, m.reboot, nil
}
func (m *mockPatchManager) ApplyUpdates(_ context.Context, _ distro.PatchFilter) (string, error) {
	return "", nil
}

func TestRunPublishesPatchReportOnInterval(t *testing.T) {
	pub := &capturingPublisher{}
	pm := &mockPatchManager{
		updates: []distro.Update{
			{Name: "openssl", CurrentVersion: "3.0.2-0ubuntu1.15", AvailableVersion: "3.0.2-0ubuntu1.16", Security: true, Source: "apt"},
		},
		reboot: false,
	}
	r := New(pub, pm, "device-patch", 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	if pub.count() < 2 {
		t.Fatalf("got %d messages, want >= 2", pub.count())
	}
	first := pub.first()
	if first.subject != "fleet.agent.device-patch.patches" {
		t.Errorf("subject = %q", first.subject)
	}
	var rep lmdmv1.PatchReport
	if err := proto.Unmarshal(first.data, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.GetDeviceId().GetId() != "device-patch" {
		t.Errorf("device_id = %q", rep.GetDeviceId().GetId())
	}
	if len(rep.GetUpdates()) != 1 || rep.GetUpdates()[0].GetName() != "openssl" {
		t.Errorf("updates = %+v", rep.GetUpdates())
	}
	if rep.GetUpdates()[0].GetSecurity() != true {
		t.Error("openssl should be security")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	pub := &capturingPublisher{}
	pm := &mockPatchManager{}
	r := New(pub, pm, "x", 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("must return nil on cancel, got %v", err)
	}
}
