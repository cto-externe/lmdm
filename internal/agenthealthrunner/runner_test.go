// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthrunner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

type fakePublisher struct {
	mu    sync.Mutex
	calls []publishCall
}

type publishCall struct {
	subject string
	data    []byte
}

func (p *fakePublisher) Publish(subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	p.calls = append(p.calls, publishCall{subject: subject, data: cp})
	return nil
}

func (p *fakePublisher) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func (p *fakePublisher) First() publishCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return publishCall{}
	}
	return p.calls[0]
}

type fakeCollector struct {
	calls atomic.Int64
}

func (c *fakeCollector) Collect(_ context.Context, deviceID string) *lmdmv1.HealthSnapshot {
	c.calls.Add(1)
	return &lmdmv1.HealthSnapshot{
		DeviceId:  &lmdmv1.DeviceID{Id: deviceID},
		Timestamp: timestamppb.Now(),
	}
}

func TestRun_PublishesImmediatelyOnStart(t *testing.T) {
	pub := &fakePublisher{}
	col := &fakeCollector{}
	r := New(pub, col, "dev-1", time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = r.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && pub.Len() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if pub.Len() == 0 {
		t.Fatal("expected at least one publish on startup")
	}
	first := pub.First()
	if first.subject != "fleet.agent.dev-1.health" {
		t.Errorf("unexpected subject: %q", first.subject)
	}
	var snap lmdmv1.HealthSnapshot
	if err := proto.Unmarshal(first.data, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.DeviceId == nil || snap.DeviceId.Id != "dev-1" {
		t.Errorf("device_id mismatch: %+v", snap.DeviceId)
	}

	cancel()
	<-done
}

func TestRun_TicksAtInterval(t *testing.T) {
	pub := &fakePublisher{}
	col := &fakeCollector{}
	r := New(pub, col, "dev-2", 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = r.Run(ctx)

	if got := pub.Len(); got < 3 {
		t.Errorf("expected at least 3 publishes, got %d", got)
	}
}

func TestRun_StopsOnCancel(t *testing.T) {
	pub := &fakePublisher{}
	col := &fakeCollector{}
	r := New(pub, col, "dev-3", 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err != nil {
		t.Fatalf("must return nil on cancel, got %v", err)
	}
	if pub.Len() != 0 {
		t.Errorf("must not publish after cancel, got %d", pub.Len())
	}
}
