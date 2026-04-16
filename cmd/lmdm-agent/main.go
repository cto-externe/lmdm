// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Command lmdm-agent is the LMDM endpoint binary. Two subcommands:
//
//	enroll  one-shot enrollment using a token; persists key + cert
//	run     load identity, connect to NATS, publish heartbeats
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agentbus"
	"github.com/cto-externe/lmdm/internal/agentcert"
	"github.com/cto-externe/lmdm/internal/agentenroll"
	"github.com/cto-externe/lmdm/internal/agentinventoryrunner"
	"github.com/cto-externe/lmdm/internal/agentkey"
	"github.com/cto-externe/lmdm/internal/agentpolicy"
	"github.com/cto-externe/lmdm/internal/agentrunner"
	"github.com/cto-externe/lmdm/internal/policy"
)

const agentVersion = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lmdm-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return usage()
	}
	switch os.Args[1] {
	case "enroll":
		return cmdEnroll(os.Args[2:])
	case "run":
		return cmdRun(os.Args[2:])
	case "-h", "--help", "help":
		_ = usage()
		return nil
	default:
		return usage()
	}
}

func usage() error {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  lmdm-agent enroll --token=<plaintext> --server=<grpcAddr> --data-dir=<path>")
	fmt.Fprintln(os.Stderr, "  lmdm-agent run    --data-dir=<path> --nats-url=<url>")
	return errors.New("invalid command")
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	token := fs.String("token", "", "enrollment token plaintext")
	server := fs.String("server", "", "gRPC server address (host:port)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory to persist agent identity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *server == "" {
		return errors.New("--token and --server are required")
	}

	keyPath := filepath.Join(*dataDir, "agent.key")
	idPath := filepath.Join(*dataDir, "agent.identity")

	_, agentPub, err := agentkey.LoadOrGenerate(keyPath)
	if err != nil {
		return fmt.Errorf("agent key: %w", err)
	}

	hostname, _ := os.Hostname()
	hardware := &lmdmv1.HardwareFingerprint{Hostname: hostname}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := agentenroll.Enroll(ctx, *server, *token, agentVersion, agentPub, hardware)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	if err := agentcert.Save(idPath, &agentcert.Identity{
		SignedCert: res.SignedCert,
		ServerPub:  res.ServerSigningKey,
	}); err != nil {
		return fmt.Errorf("save identity: %w", err)
	}

	fmt.Printf("enrolled: device_id=%s tenant=%s groups=%v nats=%s\n",
		res.DeviceID, res.TenantID, res.GroupIDs, res.Endpoints.GetNatsUrl())
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory containing agent identity")
	natsURL := fs.String("nats-url", "", "NATS connection URL")
	interval := fs.Duration("interval", 60*time.Second, "heartbeat interval")
	inventoryInterval := fs.Duration("inventory-interval", time.Hour, "inventory reporting interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *natsURL == "" {
		return errors.New("--nats-url is required")
	}

	idPath := filepath.Join(*dataDir, "agent.identity")
	id, err := agentcert.Load(idPath)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	deviceID, err := deviceIDFromCert(id.SignedCert)
	if err != nil {
		return fmt.Errorf("read device_id from cert: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	bus, err := agentbus.Connect(ctx, *natsURL)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer bus.Close()

	// Policy handler: subscribe to commands, apply profiles, publish compliance.
	snapRoot := filepath.Join(*dataDir, "snapshots")
	policyHandler := agentpolicy.NewHandler(
		bus.NC(),
		id.ServerPub,
		policy.DefaultRegistry(),
		deviceID,
		snapRoot,
	)
	if err := policyHandler.Start(); err != nil {
		return fmt.Errorf("policy handler: %w", err)
	}
	defer policyHandler.Stop()

	// Run heartbeat + inventory loops concurrently; first error wins, but
	// both are expected to return nil on ctx cancel.
	heartbeat := agentrunner.New(bus, deviceID, agentVersion, *interval)
	inventory := agentinventoryrunner.New(bus, deviceID, *inventoryInterval)

	errCh := make(chan error, 2)
	go func() { errCh <- heartbeat.Run(ctx) }()
	go func() { errCh <- inventory.Run(ctx) }()

	// Wait for both goroutines to finish.
	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

// deviceIDFromCert extracts the device_id field from the SignedAgentCert.
// Verification with the server pubkey is deferred to a future plan; at MVP
// we trust the cert we ourselves persisted at enrollment time.
func deviceIDFromCert(signedBytes []byte) (string, error) {
	var signed lmdmv1.SignedAgentCert
	if err := proto.Unmarshal(signedBytes, &signed); err != nil {
		return "", err
	}
	var cert lmdmv1.AgentIdentityCert
	if err := proto.Unmarshal(signed.GetCertBytes(), &cert); err != nil {
		return "", err
	}
	return cert.GetDeviceId().GetId(), nil
}

func defaultDataDir() string {
	if v := os.Getenv("LMDM_AGENT_DATA_DIR"); v != "" {
		return v
	}
	return "/var/lib/lmdm-agent"
}
