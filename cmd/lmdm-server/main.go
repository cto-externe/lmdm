// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Command lmdm-server is the LMDM control-plane entrypoint.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/api"
	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/commandresultsingester"
	"github.com/cto-externe/lmdm/internal/complianceingester"
	"github.com/cto-externe/lmdm/internal/config"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/deployments"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/grpcservices"
	"github.com/cto-externe/lmdm/internal/healthingester"
	"github.com/cto-externe/lmdm/internal/healthretention"
	"github.com/cto-externe/lmdm/internal/inventoryingester"
	"github.com/cto-externe/lmdm/internal/natsbus"
	"github.com/cto-externe/lmdm/internal/objectstore"
	"github.com/cto-externe/lmdm/internal/patchingester"
	"github.com/cto-externe/lmdm/internal/patchschedule"
	"github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/rebootingester"
	"github.com/cto-externe/lmdm/internal/revocation"
	"github.com/cto-externe/lmdm/internal/server"
	"github.com/cto-externe/lmdm/internal/serverkey"
	"github.com/cto-externe/lmdm/internal/statusingester"
	"github.com/cto-externe/lmdm/internal/tlspki"
	"github.com/cto-externe/lmdm/internal/tokens"
	"github.com/cto-externe/lmdm/internal/users"
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

	serverPriv, serverPub, err := serverkey.LoadOrGenerate(cfg.ServerSigningKeyPath)
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	slog.Info("server signing key ready", "path", cfg.ServerSigningKeyPath)

	// Load CA + server TLS leaf for mTLS transport. Failures are fatal —
	// operators are expected to run lmdm-keygen before launching the server.
	ca, err := tlspki.LoadCA(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	slog.Info("CA loaded", "cert", cfg.CACertPath)

	serverCertPEM, err := os.ReadFile(cfg.ServerCertPath) //nolint:gosec // path is an explicit configuration input
	if err != nil {
		return fmt.Errorf("read server cert: %w", err)
	}
	serverKeyPEM, err := os.ReadFile(cfg.ServerKeyPath) //nolint:gosec // path is an explicit configuration input
	if err != nil {
		return fmt.Errorf("read server key: %w", err)
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return fmt.Errorf("parse server cert: %w", err)
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(ca.Cert)

	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")

	// Revocation cache + tlsConfig must be built before the NATS connection
	// because the server authenticates to NATS with the same X.509 cert +
	// tls.Config it uses to serve gRPC/HTTP. Bootstrap from DB here; the NATS
	// broadcast subscription is wired up after NATS comes up.
	revocationRepo := revocation.New(pool)
	revCache := tlspki.NewRevocationCache()
	if serials, err := revocationRepo.ListSerials(ctx, tenantID); err != nil {
		slog.Warn("initial revocation list fetch failed", "err", err)
	} else {
		revCache.Replace(serials)
		slog.Info("revocation cache bootstrapped", "count", len(serials))
	}

	// TLS config serves both HTTP and gRPC, and is also handed to the NATS
	// client below so the server presents its cert to the broker. ClientAuth
	// is VerifyClientCertIfGiven so unauthenticated agents can still hit
	// EnrollmentService.Enroll (they don't have a cert yet); RPCs that
	// require a peer cert enforce it at the handler layer via
	// peer.FromContext. X25519MLKEM768 is preferred for PQ-hybrid key
	// exchange, with classical curves retained for compatibility.
	// VerifyConnection re-checks the revocation cache for resumed sessions
	// (Go's VerifyPeerCertificate is skipped on resumption).
	verifyConn := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return nil
		}
		if revCache.Has(cs.PeerCertificates[0].SerialNumber.String()) {
			return tlspki.ErrCertificateRevoked
		}
		return nil
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		RootCAs:      clientCAPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
		// With ClientAuth=VerifyClientCertIfGiven, unauthenticated clients (e.g.
		// agents during initial enrollment — they have no cert yet) produce an
		// empty verifiedChains. revCache.VerifyPeerCertificate strictly rejects
		// that, which would block legitimate enrollment. Wrap it so empty
		// chains pass through; revocation is still enforced on authenticated
		// sessions (and reverified for resumed sessions via VerifyConnection
		// below).
		VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
			if len(chains) == 0 {
				return nil
			}
			return revCache.VerifyPeerCertificate(raw, chains)
		},
		VerifyConnection: verifyConn,
	}

	bus, err := natsbus.Connect(ctx, cfg.NATSURL, tlsConfig)
	if err != nil {
		return fmt.Errorf("nats connect: %w", err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		return fmt.Errorf("nats streams: %w", err)
	}

	// Subscribe to revocation broadcasts + start periodic full refresh now
	// that NATS is up.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if ss, err := revocationRepo.ListSerials(ctx, tenantID); err != nil {
					slog.Warn("revocation refresh failed", "err", err)
				} else {
					revCache.Replace(ss)
				}
			}
		}
	}()
	if _, err := revocation.Subscribe(ctx, bus.NC(), revCache.Add); err != nil {
		slog.Warn("revocation broadcast subscribe failed", "err", err)
	}

	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)

	endpoints := &lmdmv1.ServerEndpoints{
		NatsUrl: cfg.NATSURL,
		GrpcUrl: cfg.GRPCAddr,
		ApiUrl:  "https://" + cfg.HTTPAddr,
	}
	enrollSvc := grpcservices.NewEnrollmentService(
		tokenRepo, deviceRepo, serverPriv, serverPub, endpoints, cfg.EnrollmentCertTTL, ca,
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

	patchIng := patchingester.New(bus, pool)
	if err := patchIng.Start(ctx); err != nil {
		return fmt.Errorf("patch ingester: %w", err)
	}
	defer patchIng.Stop()
	slog.Info("patch ingester started")

	healthIng := healthingester.New(bus, deviceRepo)
	if err := healthIng.Start(ctx); err != nil {
		return fmt.Errorf("health ingester: %w", err)
	}
	defer healthIng.Stop()
	slog.Info("health ingester started")

	pruner := healthretention.New(pool, time.Duration(cfg.HealthRetentionDays)*24*time.Hour, 24*time.Hour)
	go func() {
		if err := pruner.Run(ctx); err != nil {
			slog.Error("health retention pruner exited", "err", err)
		}
	}()
	slog.Info("health retention pruner started", "retention_days", cfg.HealthRetentionDays)

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

	// Auth plumbing: JWT signer, AES-256 master key, users repo, audit writer,
	// AuthService, and the per-route rate limiters consumed by the REST layer.
	jwtSigner, err := auth.LoadJWTSigner(cfg.JWTPrivateKeyPath, 15*time.Minute)
	if err != nil {
		return fmt.Errorf("load jwt signer: %w", err)
	}
	slog.Info("jwt signer loaded", "path", cfg.JWTPrivateKeyPath)

	encB64, err := os.ReadFile(cfg.EncKeyPath) //nolint:gosec // path is an explicit configuration input
	if err != nil {
		return fmt.Errorf("read enc key: %w", err)
	}
	encKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encB64)))
	if err != nil {
		return fmt.Errorf("decode enc key: %w", err)
	}
	if len(encKey) != 32 {
		return fmt.Errorf("enc key must decode to 32 bytes, got %d", len(encKey))
	}
	slog.Info("enc key loaded", "path", cfg.EncKeyPath)

	usersRepo := users.New(pool)
	auditWriter := audit.NewWriter(pool)

	rebootIng := rebootingester.New(bus.NC(), pool, deviceRepo, auditWriter)
	if err := rebootIng.Start(ctx); err != nil {
		return fmt.Errorf("rebootingester start: %w", err)
	}
	defer func() { _ = rebootIng.Stop() }()
	slog.Info("reboot ingester started")

	authSvc := &auth.Service{
		Users:    usersRepo,
		Audit:    auditWriter,
		Signer:   jwtSigner,
		EncKey:   encKey,
		TenantID: tenantID,
		Issuer:   "LMDM",
	}

	// Deployments: repository + event-driven state machine engine + consumer of
	// CommandResult acks from agents.
	profileRepo := profiles.NewRepository(pool, serverPriv)
	deploymentRepo := deployments.New(pool)
	deploymentEngine := deployments.NewEngine(deploymentRepo, bus.NC(), profileRepo)
	go func() {
		if err := deploymentEngine.Run(ctx); err != nil {
			slog.Error("deployment engine exited", "err", err)
		}
	}()
	slog.Info("deployment engine started")

	// Patch schedule engine (server-side cron for patch management).
	patchRepo := patchschedule.NewRepository(pool)
	patchResolver := patchschedule.NewResolver(pool.Pool)
	patchEngine := patchschedule.NewEngine(patchRepo, bus.NC(), patchResolver, deviceRepo, 60*time.Second)
	go func() {
		if err := patchEngine.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("patchschedule engine exited", "err", err)
		}
	}()
	slog.Info("patchschedule engine started")

	cmdResultsIng := commandresultsingester.New(bus, deviceRepo, deploymentEngine)
	if err := cmdResultsIng.Start(ctx); err != nil {
		return fmt.Errorf("command results ingester: %w", err)
	}
	defer cmdResultsIng.Stop()
	slog.Info("command results ingester started")

	// REST API — all endpoints under /api/v1/.
	apiDeps := &api.Deps{
		Pool:              pool,
		Devices:           deviceRepo,
		Tokens:            tokenRepo,
		Profiles:          profileRepo,
		Users:             usersRepo,
		Audit:             auditWriter,
		Auth:              authSvc,
		Signer:            jwtSigner,
		Deployments:       deploymentRepo,
		DeploymentsEngine: deploymentEngine,
		Revocation:        revocationRepo,
		LoginRateLimit:    auth.NewRateLimiter(10, 10*time.Minute),
		MFARateLimit:      auth.NewRateLimiter(60, time.Minute),
		NATS:              bus.NC(),
		TenantID:          tenantID,
		PatchRepo:         patchRepo,
	}
	mux.Handle("/api/", api.Router(apiDeps))

	srv, err := server.New(cfg.HTTPAddr, cfg.GRPCAddr, mux, tlsConfig)
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
