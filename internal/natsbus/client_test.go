package natsbus

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIntegrationConnectAndSetupStreams(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image:        "nats:2.10-alpine",
		ExposedPorts: []string{"4222/tcp", "8222/tcp"},
		Cmd:          []string{"-js", "-m", "8222"},
		WaitingFor:   wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start nats: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "4222/tcp")
	if err != nil {
		t.Fatal(err)
	}
	url := "nats://" + host + ":" + port.Port()

	bus, err := Connect(ctx, url)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer bus.Close()

	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatalf("EnsureStreams: %v", err)
	}

	names, err := bus.ListStreamNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"COMMANDS", "INVENTORY", "HEALTH", "EVENTS", "STATUS"}
	for _, want := range expected {
		found := false
		for _, got := range names {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("stream %q missing (got: %v)", want, names)
		}
	}
}
