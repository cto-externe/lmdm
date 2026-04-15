// Command lmdm-token issues an enrollment token from the command line.
// Intended for early bootstrap and admin-side scripts before the WebUI exists.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/config"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/tokens"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lmdm-token:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		description = flag.String("description", "manual", "human-readable label")
		groupCSV    = flag.String("groups", "", "comma-separated group ids")
		maxUses     = flag.Int("max-uses", 1, "maximum number of enrollments")
		ttl         = flag.Duration("ttl", 24*time.Hour, "time-to-live")
		tenant      = flag.String("tenant", "00000000-0000-0000-0000-000000000000", "tenant uuid")
		createdBy   = flag.String("created-by", "cli", "actor name for audit")
	)
	flag.Parse()

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := db.MigrateUp(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	tenantID, err := uuid.Parse(*tenant)
	if err != nil {
		return fmt.Errorf("invalid tenant uuid: %w", err)
	}
	groupIDs := []string{}
	if *groupCSV != "" {
		for _, g := range strings.Split(*groupCSV, ",") {
			g = strings.TrimSpace(g)
			if g != "" {
				groupIDs = append(groupIDs, g)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}
	defer pool.Close()

	repo := tokens.NewRepository(pool)
	plaintext, tok, err := repo.Create(ctx, tokens.CreateRequest{
		TenantID:    tenantID,
		Description: *description,
		GroupIDs:    groupIDs,
		MaxUses:     *maxUses,
		TTL:         *ttl,
		CreatedBy:   *createdBy,
	})
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}

	// Print clearly so a human can copy/paste.
	fmt.Println("=================================================================")
	fmt.Println("Enrollment token created. SHOW THIS TO THE USER ONCE — never logged.")
	fmt.Println("=================================================================")
	fmt.Printf("token        : %s\n", plaintext)
	fmt.Printf("token_id     : %s\n", tok.ID)
	fmt.Printf("tenant_id    : %s\n", tok.TenantID)
	fmt.Printf("description  : %s\n", tok.Description)
	fmt.Printf("groups       : %v\n", tok.GroupIDs)
	fmt.Printf("max_uses     : %d\n", tok.MaxUses)
	fmt.Printf("expires_at   : %s\n", tok.ExpiresAt.Format(time.RFC3339))
	fmt.Println("=================================================================")
	return nil
}
