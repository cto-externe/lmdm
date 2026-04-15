package db

import (
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	// pgx5 driver registration (blank-import): golang-migrate looks up the
	// "pgx5://" URL scheme via init-registered drivers, so this package must
	// be imported for its side effects even though nothing is referenced.
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrateUp applies all pending migrations embedded in the binary.
// It is safe to call multiple times: already-applied migrations are skipped.
func MigrateUp(dsn string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("db: migrations source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, "pgx5://"+stripScheme(dsn))
	if err != nil {
		return fmt.Errorf("db: migrate init: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("db: migrate up: %w", err)
	}
	return nil
}

func stripScheme(dsn string) string {
	const prefix = "postgres://"
	if len(dsn) > len(prefix) && dsn[:len(prefix)] == prefix {
		return dsn[len(prefix):]
	}
	const prefix2 = "postgresql://"
	if len(dsn) > len(prefix2) && dsn[:len(prefix2)] == prefix2 {
		return dsn[len(prefix2):]
	}
	return dsn
}
