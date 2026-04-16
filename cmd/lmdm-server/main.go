// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Command lmdm-server is the LMDM control-plane entrypoint.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/api"
	"github.com/cto-externe/lmdm/internal/complianceingester"
	"github.com/cto-externe/lmdm/internal/config"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/grpcservices"
	"github.com/cto-externe/lmdm/internal/inventoryingester"
	"github.com/cto-externe/lmdm/internal/natsbus"
	"github.com/cto-externe/lmdm/internal/objectstore"
	"github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/server"
	"github.com/cto-externe/lmdm/internal/serverkey"
	"github.com/cto-externe/lmdm/internal/statusingester"
	"github.com/cto-externe/lmdm/internal/tokens"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := db.MigrateUp(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}
	defer pool.Close()

	bus, err := natsbus.Connect(ctx, cfg.NATSURL)
	if err != nil {
		return fmt.Errorf("nats connect: %w", err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		return fmt.Errorf("nats streams: %w", err)
	}

	serverPriv, serverPub, err := serverkey.LoadOrGenerate(cfg.ServerKeyPath)
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	slog.Info("server signing key ready", "path", cfg.ServerKeyPath)

	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)

	endpoints := &lmdmv1.ServerEndpoints{
		NatsUrl: cfg.NATSURL,
		GrpcUrl: cfg.GRPCAddr,
		ApiUrl:  "http://" + cfg.HTTPAddr,
	}
	enrollSvc := grpcservices.NewEnrollmentService(
		tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, cfg.EnrollmentCertTTL,
	)

	ingester := statusingester.New(bus, deviceRepo)
	if err := ingester.Start(ctx); err != nil {
		return fmt.Errorf("status ingester: %w", err)
	}
	defer ingester.Stop()
	slog.Info("status ingester started")

	invIngester := inventoryingester.New(bus, deviceRepo)
	if err := invIngester.Start(ctx); err != nil {
		return fmt.Errorf("inventory ingester: %w", err)
	}
	defer invIngester.Stop()
	slog.Info("inventory ingester started")

	compIng := complianceingester.New(bus, pool)
	if err := compIng.Start(ctx); err != nil {
		return fmt.Errorf("compliance ingester: %w", err)
	}
	defer compIng.Stop()
	slog.Info("compliance ingester started")

	store, err := objectstore.New(objectstore.Config{
		Endpoint:  cfg.S3Endpoint,
		Region:    cfg.S3Region,
		Bucket:    cfg.S3Bucket,
		AccessKey: cfg.S3AccessKey,
		SecretKey: cfg.S3SecretKey,
		PathStyle: true,
	})
	if err != nil {
		return fmt.Errorf("objectstore: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", server.NewHealthHandler(map[string]server.HealthChecker{
		"db": server.HealthCheckerFunc(func(ctx context.Context) error { return pool.Ping(ctx) }),
		"nats": server.HealthCheckerFunc(func(ctx context.Context) error {
			_, err := bus.ListStreamNames(ctx)
			return err
		}),
		"s3": server.HealthCheckerFunc(func(ctx context.Context) error {
			return store.Ping(ctx)
		}),
	}))

	// REST API — all endpoints under /api/v1/.
	apiDeps := &api.Deps{
		Pool:     pool,
		Devices:  deviceRepo,
		Tokens:   tokenRepo,
		Profiles: profiles.NewRepository(pool, serverPriv),
		NATS:     bus.NC(),
		TenantID: uuid.MustParse("00000000-0000-0000-0000-000000000000"),
	}
	mux.Handle("/api/", api.Router(apiDeps))

	srv, err := server.New(cfg.HTTPAddr, cfg.GRPCAddr, mux)
	if err != nil {
		return fmt.Errorf("server new: %w", err)
	}

	lmdmv1.RegisterEnrollmentServiceServer(srv.GRPC(), enrollSvc)

	errs := srv.Start()
	slog.Info("lmdm-server started", "http", cfg.HTTPAddr, "grpc", cfg.GRPCAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errs:
		return err
	case s := <-sig:
		slog.Info("shutdown requested", "signal", s.String())
	}

	return srv.Shutdown(10 * time.Second)
}
