// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Command lmdm-agent is the LMDM endpoint binary. Two subcommands:
//
//	enroll  one-shot enrollment using a token; persists key + cert
//	run     load identity, connect to NATS, publish heartbeats
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agentbus"
	"github.com/cto-externe/lmdm/internal/agentcert"
	"github.com/cto-externe/lmdm/internal/agentenroll"
	"github.com/cto-externe/lmdm/internal/agenthealth"
	"github.com/cto-externe/lmdm/internal/agenthealthrunner"
	"github.com/cto-externe/lmdm/internal/agentinventoryrunner"
	"github.com/cto-externe/lmdm/internal/agentkey"
	"github.com/cto-externe/lmdm/internal/agentpatchrunner"
	"github.com/cto-externe/lmdm/internal/agentpolicy"
	"github.com/cto-externe/lmdm/internal/agentrunner"
	"github.com/cto-externe/lmdm/internal/distro"
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
	complianceInterval := fs.Duration("compliance-interval", time.Hour, "compliance drift check interval")
	patchInterval := fs.Duration("patch-interval", 6*time.Hour, "patch detection interval")
	healthInterval := fs.Duration("health-interval", 6*time.Hour, "Health snapshot collection interval")
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

	// Detect OS family for patch management.
	osFamily := detectOSFamily()
	var pm distro.PatchManager
	if mgr, err := distro.NewPatchManager(osFamily); err != nil {
		slog.Warn("patch manager not available", "family", osFamily, "err", err)
	} else {
		pm = mgr
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
	profileStore := agentpolicy.NewProfileStore(filepath.Join(*dataDir, "profiles"))
	policyHandler := agentpolicy.NewHandler(agentpolicy.HandlerOptions{
		NC:        bus.NC(),
		ServerPub: id.ServerPub,
		Registry:  policy.DefaultRegistry(),
		DeviceID:  deviceID,
		SnapRoot:  snapRoot,
		Store:     profileStore,
		PM:        pm,
	})
	if err := policyHandler.Start(); err != nil {
		return fmt.Errorf("policy handler: %w", err)
	}
	defer policyHandler.Stop()

	// Run heartbeat + inventory + drift loops concurrently; first error wins,
	// but all are expected to return nil on ctx cancel.
	heartbeat := agentrunner.New(bus, deviceID, agentVersion, *interval)
	inventory := agentinventoryrunner.New(bus, deviceID, *inventoryInterval)
	driftRunner := agentpolicy.NewDriftRunner(bus, policy.DefaultRegistry(), profileStore, deviceID, *complianceInterval)

	goroutines := 3 // heartbeat + inventory + drift
	if pm != nil {
		goroutines++
	}
	goroutines++ // health (always on)
	errCh := make(chan error, goroutines)
	go func() { errCh <- heartbeat.Run(ctx) }()
	go func() { errCh <- inventory.Run(ctx) }()
	go func() { errCh <- driftRunner.Run(ctx) }()
	if pm != nil {
		patchRunner := agentpatchrunner.New(bus, pm, deviceID, *patchInterval)
		go func() { errCh <- patchRunner.Run(ctx) }()
	}
	healthCollector := agenthealth.NewCollector(agenthealth.NewExecCommandRunner())
	healthRunner := agenthealthrunner.New(bus, healthCollector, deviceID, *healthInterval)
	go func() { errCh <- healthRunner.Run(ctx) }()

	// Wait for all goroutines to finish.
	var firstErr error
	for i := 0; i < goroutines; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

func detectOSFamily() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var id, idLike string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
		if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		}
	}
	all := strings.ToLower(id + " " + idLike)
	switch {
	case strings.Contains(all, "debian") || strings.Contains(all, "ubuntu") || strings.Contains(all, "mint"):
		return "debian"
	case strings.Contains(all, "rhel") || strings.Contains(all, "fedora") || strings.Contains(all, "centos") || strings.Contains(all, "alma") || strings.Contains(all, "rocky"):
		return "rhel"
	case strings.Contains(all, "nixos"):
		return "nixos"
	default:
		return id
	}
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
