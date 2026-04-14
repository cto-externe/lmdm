// Package db wraps the pgx connection pool used by the LMDM server.
// It is intentionally minimal: higher-level persistence lives in feature
// packages that will build on this connection.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool is a thin wrapper around *pgxpool.Pool. Keeping it as a distinct type
// makes future cross-cutting concerns (tenant_id session var, tracing) easier
// to add in one place.
type Pool struct {
	*pgxpool.Pool
}

// Open connects to PostgreSQL and returns a ready-to-use pool. The caller is
// responsible for calling Close when done.
func Open(ctx context.Context, dsn string) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &Pool{Pool: pool}, nil
}
