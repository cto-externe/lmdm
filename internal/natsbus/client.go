// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package natsbus wraps the NATS + JetStream setup used by the LMDM server.
// Streams and their retention policies are declared here so one place
// documents the messaging topology.
package natsbus

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Bus is a connection to NATS + JetStream.
type Bus struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// Connect establishes a NATS connection tuned for LMDM operations:
// infinite reconnect with exponential backoff + jitter, large buffer during
// outages, and ping-based liveness detection.
func Connect(_ context.Context, url string) (*Bus, error) {
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
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("natsbus: connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("natsbus: jetstream: %w", err)
	}
	return &Bus{nc: nc, js: js}, nil
}

// JetStream returns the underlying JetStream context. Used by feature
// packages that need to create their own consumers.
func (b *Bus) JetStream() jetstream.JetStream { return b.js }

// Close drains and closes the underlying NATS connection.
func (b *Bus) Close() {
	if b == nil || b.nc == nil {
		return
	}
	_ = b.nc.Drain()
}

// StreamSpec describes a JetStream stream LMDM expects to exist.
type StreamSpec struct {
	Name      string
	Subjects  []string
	Retention time.Duration
}

// streams is the canonical list of JetStream streams used by LMDM. Retention
// policies match the architecture spec §8.3.
var streams = []StreamSpec{
	{"COMMANDS", []string{"fleet.agent.*.commands", "fleet.group.*.commands", "fleet.global.commands"}, 7 * 24 * time.Hour},
	{"INVENTORY", []string{"fleet.agent.*.inventory", "fleet.agent.*.compliance", "fleet.agent.*.printers"}, 24 * time.Hour},
	{"HEALTH", []string{"fleet.agent.*.health"}, 7 * 24 * time.Hour},
	{"EVENTS", []string{"fleet.agent.*.events"}, 30 * 24 * time.Hour},
	{"STATUS", []string{"fleet.agent.*.status"}, 1 * time.Hour},
}

// EnsureStreams creates or updates the JetStream streams required by LMDM.
// It is safe to call repeatedly (idempotent).
func (b *Bus) EnsureStreams(ctx context.Context) error {
	for _, s := range streams {
		cfg := jetstream.StreamConfig{
			Name:      s.Name,
			Subjects:  s.Subjects,
			Retention: jetstream.LimitsPolicy,
			MaxAge:    s.Retention,
			Storage:   jetstream.FileStorage,
		}
		if _, err := b.js.CreateOrUpdateStream(ctx, cfg); err != nil {
			return fmt.Errorf("natsbus: stream %s: %w", s.Name, err)
		}
	}
	return nil
}

// ListStreamNames returns the names of the streams currently known to
// JetStream. Used by tests and by the /healthz endpoint later on.
func (b *Bus) ListStreamNames(ctx context.Context) ([]string, error) {
	out := []string{}
	lister := b.js.StreamNames(ctx)
	for name := range lister.Name() {
		out = append(out, name)
	}
	if err := lister.Err(); err != nil {
		return nil, fmt.Errorf("natsbus: list streams: %w", err)
	}
	return out, nil
}
