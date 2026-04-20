// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package revocation

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nats-io/nats.go"
)

// BroadcastSubject is the NATS subject for revocation broadcasts.
const BroadcastSubject = "fleet.broadcast.cert_revoked"

// NATSClient is the minimal NATS surface we need.
type NATSClient interface {
	Publish(subject string, data []byte) error
	Subscribe(subject string, cb nats.MsgHandler) (*nats.Subscription, error)
}

// Publish sends a single serial to the broadcast subject. Payload is the raw
// serial number as bytes (no proto wrapper — small tight message).
func Publish(nc NATSClient, serial string) error {
	if err := nc.Publish(BroadcastSubject, []byte(serial)); err != nil {
		return fmt.Errorf("revocation: broadcast publish: %w", err)
	}
	return nil
}

// Subscribe subscribes to the broadcast and calls handler for each serial.
// Stops on ctx cancel.
func Subscribe(ctx context.Context, nc NATSClient, handler func(serial string)) (*nats.Subscription, error) {
	sub, err := nc.Subscribe(BroadcastSubject, func(msg *nats.Msg) {
		serial := string(msg.Data)
		if serial == "" {
			slog.Warn("revocation: empty broadcast message")
			return
		}
		handler(serial)
	})
	if err != nil {
		return nil, fmt.Errorf("revocation: broadcast subscribe: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = sub.Unsubscribe()
	}()
	return sub, nil
}
