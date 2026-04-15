// Package agentbus is the agent-side NATS connection wrapper. Publish-only
// at this stage; the agent never creates JetStream streams (the server does
// that on startup).
package agentbus

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/nats-io/nats.go"
)

// Bus is a NATS connection owned by the agent.
type Bus struct {
	nc *nats.Conn
}

// Connect dials NATS with reconnect/jitter options matching the architecture
// spec §8A.3 (infinite reconnect, exponential backoff with 30% jitter, large
// reconnect buffer).
func Connect(_ context.Context, url string) (*Bus, error) {
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.CustomReconnectDelay(func(n int) time.Duration {
			base := math.Min(float64(n)*2, 300)
			jitter := rand.Float64() * base * 0.3 //nolint:gosec // non-crypto jitter for reconnect backoff
			return time.Duration(base+jitter) * time.Second
		}),
		nats.ReconnectBufSize(16 * 1024 * 1024),
		nats.PingInterval(30 * time.Second),
		nats.MaxPingsOutstanding(3),
		nats.RetryOnFailedConnect(true),
	}
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("agentbus: connect: %w", err)
	}
	return &Bus{nc: nc}, nil
}

// Publish sends data on the given subject. Returns an error if NATS rejects
// it synchronously (e.g., not connected and buffer full).
func (b *Bus) Publish(subject string, data []byte) error {
	if err := b.nc.Publish(subject, data); err != nil {
		return fmt.Errorf("agentbus: publish %s: %w", subject, err)
	}
	return nil
}

// Close drains and closes the underlying NATS connection.
func (b *Bus) Close() {
	if b == nil || b.nc == nil {
		return
	}
	_ = b.nc.Drain()
}
