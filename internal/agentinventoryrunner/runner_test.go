// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventoryrunner

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
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

func TestRunPublishesInventoryOnInterval(t *testing.T) {
	pub := &capturingPublisher{}
	r := New(pub, "device-inv", 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	// Initial send + ~4 ticks → expect >= 3.
	if pub.count() < 3 {
		t.Fatalf("got %d messages, want >= 3", pub.count())
	}
	first := pub.first()
	if first.subject != "fleet.agent.device-inv.inventory" {
		t.Errorf("subject = %q", first.subject)
	}
	var rep lmdmv1.InventoryReport
	if err := proto.Unmarshal(first.data, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.GetDeviceId().GetId() != "device-inv" {
		t.Errorf("device_id = %q", rep.GetDeviceId().GetId())
	}
	if !rep.GetIsFull() {
		t.Error("is_full must be true")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	pub := &capturingPublisher{}
	r := New(pub, "x", 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run on cancelled ctx must return nil, got %v", err)
	}
}
