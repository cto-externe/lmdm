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

	"github.com/cto-externe/lmdm/internal/config"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/natsbus"
	"github.com/cto-externe/lmdm/internal/objectstore"
	"github.com/cto-externe/lmdm/internal/server"
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

	srv, err := server.New(cfg.HTTPAddr, cfg.GRPCAddr, mux)
	if err != nil {
		return fmt.Errorf("server new: %w", err)
	}

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
