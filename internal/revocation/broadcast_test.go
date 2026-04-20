// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package revocation

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startNATS(t *testing.T) (*nats.Conn, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	req := testcontainers.ContainerRequest{
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		Cmd:          []string{"-js"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		cancel()
		t.Fatalf("start nats: %v", err)
	}

	host, err := c.Host(ctx)
	if err != nil {
		_ = c.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "4222/tcp")
	if err != nil {
		_ = c.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	url := "nats://" + host + ":" + port.Port()

	nc, err := nats.Connect(url, nats.Timeout(10*time.Second))
	if err != nil {
		_ = c.Terminate(ctx)
		cancel()
		t.Fatalf("nats.Connect: %v", err)
	}

	cleanup := func() {
		nc.Close()
		_ = c.Terminate(ctx)
		cancel()
	}
	return nc, cleanup
}

func TestIntegrationPublishSubscribe_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	nc, cleanup := startNATS(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan string, 1)
	sub, err := Subscribe(ctx, nc, func(serial string) {
		select {
		case got <- serial:
		default:
		}
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	// Ensure the subscription is fully registered on the server before publish.
	if err := nc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	const want = "serial-roundtrip"
	if err := Publish(nc, want); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case serial := <-got:
		if serial != want {
			t.Errorf("handler received %q, want %q", serial, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: handler did not receive serial within 1s")
	}
}

func TestIntegrationSubscribe_ContextCancel_Unsubscribes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	nc, cleanup := startNATS(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())

	received := make(chan string, 8)
	_, err := Subscribe(ctx, nc, func(serial string) {
		select {
		case received <- serial:
		default:
		}
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Cancel and give the goroutine a moment to run Unsubscribe.
	cancel()
	// Allow the goroutine scheduled in Subscribe to unsubscribe.
	time.Sleep(200 * time.Millisecond)
	if err := nc.Flush(); err != nil {
		t.Fatalf("Flush after cancel: %v", err)
	}

	// Drain anything that may have arrived before cancel took effect.
	for len(received) > 0 {
		<-received
	}

	// Publish AFTER cancel; the unsubscribe should prevent delivery.
	if err := Publish(nc, "post-cancel"); err != nil {
		t.Fatalf("Publish after cancel: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	select {
	case serial := <-received:
		t.Errorf("received %q after context cancel, want no delivery", serial)
	case <-time.After(300 * time.Millisecond):
		// success: nothing delivered
	}
}
