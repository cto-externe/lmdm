// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

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
	"github.com/nats-io/nats.go/jetstream"
)

// Bus is a NATS connection owned by the agent.
type Bus struct {
	nc *nats.Conn
	js jetstream.JetStream // nil-safe — populated by EnableJetStream
}

// Connect dials NATS with reconnect/jitter options matching the architecture
// spec §8A.3 (infinite reconnect, exponential backoff with jitter, large
// reconnect buffer). Honors ctx cancellation: if ctx is done before the
// initial connect returns, Connect returns ctx.Err() and the background
// connect result (if any) is closed once it arrives.
func Connect(ctx context.Context, url string) (*Bus, error) {
	opts := []nats.Option{
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2 * time.Second),
		nats.CustomReconnectDelay(func(n int) time.Duration {
			base := math.Min(float64(n+1)*2, 300)
			jitter := rand.Float64() * base * 0.3 //nolint:gosec // non-crypto jitter for reconnect backoff
			return time.Duration(base+jitter) * time.Second
		}),
		nats.ReconnectBufSize(16 * 1024 * 1024),
		nats.PingInterval(30 * time.Second),
		nats.MaxPingsOutstanding(3),
		nats.RetryOnFailedConnect(true),
	}

	type result struct {
		nc  *nats.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		nc, err := nats.Connect(url, opts...)
		ch <- result{nc: nc, err: err}
	}()

	select {
	case <-ctx.Done():
		// Ensure we don't leak the background connection if it succeeds later.
		go func() {
			r := <-ch
			if r.nc != nil {
				r.nc.Close()
			}
		}()
		return nil, fmt.Errorf("agentbus: connect: %w", ctx.Err())
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("agentbus: connect: %w", r.err)
		}
		return &Bus{nc: r.nc}, nil
	}
}

// Publish sends data on the given subject. Returns an error if NATS rejects
// it synchronously (e.g., not connected and buffer full).
func (b *Bus) Publish(subject string, data []byte) error {
	if err := b.nc.Publish(subject, data); err != nil {
		return fmt.Errorf("agentbus: publish %s: %w", subject, err)
	}
	return nil
}

// NC returns the underlying *nats.Conn for consumers that need subscription
// access (e.g., the policy handler). Use sparingly.
func (b *Bus) NC() *nats.Conn { return b.nc }

// EnableJetStream opens the JetStream context. Call once after Connect on
// agents that need ack-bearing publishes (e.g. the deployment watchdog).
func (b *Bus) EnableJetStream() error {
	if b.js != nil {
		return nil
	}
	js, err := jetstream.New(b.nc)
	if err != nil {
		return fmt.Errorf("agentbus: enable jetstream: %w", err)
	}
	b.js = js
	return nil
}

// PublishWithAck publishes data on subject and waits for the JetStream ack
// (i.e. confirmation the broker accepted and stored the message in the
// matching stream). Used by the deployment watchdog to confirm the server
// will see the CommandResult before clearing the pending state.
//
// Returns ctx.Err() on deadline/cancel, or a wrapped error from JetStream.
func (b *Bus) PublishWithAck(ctx context.Context, subject string, data []byte) error {
	if b.js == nil {
		return fmt.Errorf("agentbus: jetstream not enabled")
	}
	if _, err := b.js.Publish(ctx, subject, data); err != nil {
		return fmt.Errorf("agentbus: publish-ack %s: %w", subject, err)
	}
	return nil
}

// AckProbe forces a synchronous round-trip with the broker via
// nc.FlushWithContext. Returns nil when the broker is reachable. Used by
// the system.nats_reachable built-in health check.
func (b *Bus) AckProbe(ctx context.Context) error {
	if err := b.nc.FlushWithContext(ctx); err != nil {
		return fmt.Errorf("agentbus: flush probe: %w", err)
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
