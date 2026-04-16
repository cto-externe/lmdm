// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Command lmdm-profile manages profile lifecycle from the CLI.
// Subcommands: create, assign.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/config"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/serverkey"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lmdm-profile:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return usage()
	}
	switch os.Args[1] {
	case "create":
		return cmdCreate(os.Args[2:])
	case "assign":
		return cmdAssign(os.Args[2:])
	default:
		return usage()
	}
}

func usage() error {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  lmdm-profile create <file.yaml>")
	fmt.Fprintln(os.Stderr, "  lmdm-profile assign <profile-id> <device-id> [--nats-url=...]")
	return errors.New("invalid command")
}

func cmdCreate(args []string) error {
	if len(args) < 1 {
		return errors.New("create requires a YAML file argument")
	}
	filePath := args[0]

	cfg, _ := config.Load(os.Getenv)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.MigrateUp(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	serverPriv, _, err := serverkey.LoadOrGenerate(cfg.ServerKeyPath)
	if err != nil {
		return err
	}

	yamlBytes, err := os.ReadFile(filePath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read %s: %w", filePath, err)
	}

	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	repo := profiles.NewRepository(pool, serverPriv)
	p, err := repo.Create(ctx, tenantID, yamlBytes)
	if err != nil {
		return err
	}

	fmt.Printf("profile created: id=%s name=%s version=%s\n", p.ID, p.Name, p.Version)
	return nil
}

func cmdAssign(args []string) error {
	fs := flag.NewFlagSet("assign", flag.ContinueOnError)
	natsURL := fs.String("nats-url", "nats://localhost:4222", "NATS URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	remaining := fs.Args()
	if len(remaining) < 2 {
		return errors.New("assign requires <profile-id> <device-id>")
	}
	profileID := uuid.MustParse(remaining[0])
	deviceID := uuid.MustParse(remaining[1])

	cfg, _ := config.Load(os.Getenv)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := db.MigrateUp(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	serverPriv, _, err := serverkey.LoadOrGenerate(cfg.ServerKeyPath)
	if err != nil {
		return err
	}

	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	repo := profiles.NewRepository(pool, serverPriv)

	if err := repo.Assign(ctx, tenantID, profileID, "device", deviceID); err != nil {
		return err
	}

	p, err := repo.FindByID(ctx, tenantID, profileID)
	if err != nil {
		return err
	}

	cmdID := uuid.NewString()
	env := &lmdmv1.CommandEnvelope{
		CommandId: cmdID,
		Command: &lmdmv1.CommandEnvelope_ApplyProfile{
			ApplyProfile: &lmdmv1.ApplyProfileCommand{
				ProfileId:      &lmdmv1.ProfileID{Id: profileID.String()},
				Version:        p.Version,
				ProfileContent: []byte(p.YAMLContent),
				ProfileSignature: &lmdmv1.HybridSignature{
					Ed25519: p.SignatureEd25519,
					MlDsa:   p.SignatureMLDSA,
				},
			},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}

	nc, err := nats.Connect(*natsURL)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer nc.Close()

	subject := "fleet.agent." + deviceID.String() + ".commands"
	if err := nc.Publish(subject, data); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	_ = nc.Flush()

	fmt.Printf("profile %s assigned to device %s and pushed via NATS\n", profileID, deviceID)
	return nil
}
