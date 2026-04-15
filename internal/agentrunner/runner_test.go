package agentrunner

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
	msgs []capturedMsg
}

type capturedMsg struct {
	subject string
	data    []byte
}

func (p *capturingPublisher) Publish(subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	p.msgs = append(p.msgs, capturedMsg{subject: subject, data: cp})
	return nil
}

func (p *capturingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.msgs)
}

func (p *capturingPublisher) first() capturedMsg {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.msgs) == 0 {
		return capturedMsg{}
	}
	return p.msgs[0]
}

func TestRunPublishesHeartbeatsOnInterval(t *testing.T) {
	pub := &capturingPublisher{}
	r := New(pub, "device-abc", "0.1.0-test", 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = r.Run(ctx)

	// Within 250ms at 50ms cadence we expect at least 3 heartbeats (the first
	// one is sent immediately, then every 50ms).
	if got := pub.count(); got < 3 {
		t.Fatalf("got %d heartbeats, want >= 3", got)
	}

	first := pub.first()
	if first.subject != "fleet.agent.device-abc.status" {
		t.Errorf("subject = %q", first.subject)
	}
	var hb lmdmv1.Heartbeat
	if err := proto.Unmarshal(first.data, &hb); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if hb.GetDeviceId().GetId() != "device-abc" {
		t.Errorf("device_id = %q", hb.GetDeviceId().GetId())
	}
	if hb.GetAgentVersion() != "0.1.0-test" {
		t.Errorf("agent_version = %q", hb.GetAgentVersion())
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	pub := &capturingPublisher{}
	r := New(pub, "device-abc", "0.1.0-test", 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled immediately
	if err := r.Run(ctx); err != nil {
		t.Fatalf("Run on cancelled ctx must return nil, got %v", err)
	}
}
