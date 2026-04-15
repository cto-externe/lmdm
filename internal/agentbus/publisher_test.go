package agentbus

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIntegrationPublishRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp"},
		Cmd:          []string{"-js"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, _ := c.Host(ctx)
	port, _ := c.MappedPort(ctx, "4222/tcp")
	url := "nats://" + host + ":" + port.Port()

	bus, err := Connect(ctx, url)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer bus.Close()

	// Subscribe before publish.
	subnc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer subnc.Close()
	ch := make(chan *nats.Msg, 1)
	if _, err := subnc.ChanSubscribe("test.subject", ch); err != nil {
		t.Fatal(err)
	}

	// Give subscriber time to register
	time.Sleep(100 * time.Millisecond)

	if err := bus.Publish("test.subject", []byte("hello")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	select {
	case msg := <-ch:
		if string(msg.Data) != "hello" {
			t.Errorf("payload = %q", msg.Data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("subscriber timed out")
	}
}
