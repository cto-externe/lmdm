// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// lmdm-user manages console accounts: bootstraps the first admin with an atomic
// TOTP enrolment, lists users, resets passwords, deactivates, and unlocks.
//
// Environment:
//
//	LMDM_PG_DSN         postgres connection string (required)
//	LMDM_ENC_KEY_PATH   path to AES-256 master key (base64, produced by lmdm-keygen).
//	                    Required for subcommands that touch TOTP secrets.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/term"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/users"
)

// Default Community tenant (matches migration 0001).
const defaultTenant = "00000000-0000-0000-0000-000000000000"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	rest := os.Args[2:]

	// Validate the subcommand before opening any resources so that
	// `defer pool.Close()` always runs when we have a pool.
	switch sub {
	case "create-admin", "list", "reset-password", "deactivate", "unlock":
	default:
		usage()
		os.Exit(2)
	}

	ctx := context.Background()
	dsn := mustEnv("LMDM_PG_DSN")
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		fail("db: " + err.Error())
	}
	defer pool.Close()
	r := users.New(pool)
	tenantID := uuid.MustParse(defaultTenant)

	switch sub {
	case "create-admin":
		createAdmin(ctx, r, tenantID, rest)
	case "list":
		list(ctx, r, tenantID)
	case "reset-password":
		resetPassword(ctx, r, tenantID, rest)
	case "deactivate":
		deactivate(ctx, r, tenantID, rest)
	case "unlock":
		unlock(ctx, r, tenantID, rest)
	}
}

func createAdmin(ctx context.Context, r *users.Repository, tenantID uuid.UUID, args []string) {
	email := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--email" && i+1 < len(args) {
			email = args[i+1]
		}
	}
	if email == "" {
		fail("usage: lmdm-user create-admin --email <addr>")
	}

	encKey := loadEncKey()

	fd := int(os.Stdin.Fd()) //nolint:gosec // stdin fd fits in int on all supported platforms
	fmt.Printf("New admin password (min %d chars): ", auth.MinPasswordLen)
	pw1, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		fail("read password: " + err.Error())
	}
	if len(pw1) < auth.MinPasswordLen {
		fail(fmt.Sprintf("password too short (min %d)", auth.MinPasswordLen))
	}
	fmt.Print("Confirm password: ")
	pw2, _ := term.ReadPassword(fd)
	fmt.Println()
	if string(pw1) != string(pw2) {
		fail("passwords do not match")
	}

	hash, err := auth.HashPassword(string(pw1))
	if err != nil {
		fail(err.Error())
	}

	u, err := r.Create(ctx, tenantID, email, hash, "admin")
	if err != nil {
		if errors.Is(err, users.ErrDuplicateEmail) {
			fail(fmt.Sprintf("a user with email %q already exists", email))
		}
		fail("create: " + err.Error())
	}

	// Atomic TOTP enrolment.
	enr, err := auth.EnrollTOTP(email, "LMDM")
	if err != nil {
		fail("totp: " + err.Error())
	}
	ct, err := auth.Encrypt(encKey, []byte(enr.Secret))
	if err != nil {
		fail("encrypt totp: " + err.Error())
	}
	if err := r.SetTOTP(ctx, tenantID, u.ID, ct); err != nil {
		fail("set totp: " + err.Error())
	}

	fmt.Println("Admin created successfully.")
	fmt.Println()
	fmt.Println("TOTP secret (save now — not stored in plaintext):")
	fmt.Println("  " + enr.Secret)
	fmt.Println("otpauth URI (scan with your authenticator app):")
	fmt.Println("  " + enr.URI)
	fmt.Println()
	fmt.Println("Next: POST /api/v1/auth/login with email+password, then /api/v1/auth/mfa/verify with the TOTP code.")
}

func list(ctx context.Context, r *users.Repository, tenantID uuid.UUID) {
	out, err := r.List(ctx, tenantID, users.ListFilter{})
	if err != nil {
		fail(err.Error())
	}
	fmt.Printf("%-36s  %-28s  %-8s  %-6s  %s\n", "ID", "EMAIL", "ROLE", "ACTIVE", "LAST LOGIN")
	for _, u := range out {
		ll := "-"
		if u.LastLoginAt != nil {
			ll = u.LastLoginAt.Format("2006-01-02T15:04:05Z")
		}
		fmt.Printf("%-36s  %-28s  %-8s  %-6t  %s\n", u.ID, u.Email, u.Role, u.Active, ll)
	}
}

func resetPassword(ctx context.Context, r *users.Repository, tenantID uuid.UUID, args []string) {
	if len(args) < 1 {
		fail("usage: lmdm-user reset-password <email>")
	}
	u, err := r.FindByEmail(ctx, tenantID, args[0])
	if err != nil {
		fail(err.Error())
	}
	tempPw, err := auth.RandomPassword(16)
	if err != nil {
		fail(err.Error())
	}
	hash, err := auth.HashPassword(tempPw)
	if err != nil {
		fail(err.Error())
	}
	if err := r.SetPasswordHash(ctx, tenantID, u.ID, hash, true); err != nil {
		fail(err.Error())
	}
	fmt.Println("Temporary password (shown once):")
	fmt.Println("  " + tempPw)
	fmt.Println("User must change password at next login.")
}

func deactivate(ctx context.Context, r *users.Repository, tenantID uuid.UUID, args []string) {
	if len(args) < 1 {
		fail("usage: lmdm-user deactivate <email>")
	}
	u, err := r.FindByEmail(ctx, tenantID, args[0])
	if err != nil {
		fail(err.Error())
	}
	// From a headless CLI we have no actor principal; use the target's own ID
	// as "byUserID" so the deactivation is traceable even though we can't
	// attribute it to a console user.
	if err := r.Deactivate(ctx, tenantID, u.ID, u.ID); err != nil {
		fail(err.Error())
	}
	fmt.Println("Deactivated:", u.Email)
}

func unlock(ctx context.Context, r *users.Repository, tenantID uuid.UUID, args []string) {
	if len(args) < 1 {
		fail("usage: lmdm-user unlock <email>")
	}
	u, err := r.FindByEmail(ctx, tenantID, args[0])
	if err != nil {
		fail(err.Error())
	}
	if err := r.Unlock(ctx, tenantID, u.ID); err != nil {
		fail(err.Error())
	}
	fmt.Println("Unlocked:", u.Email)
}

func loadEncKey() []byte {
	path := os.Getenv("LMDM_ENC_KEY_PATH")
	if path == "" {
		fail("LMDM_ENC_KEY_PATH not set (run lmdm-keygen first)")
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is an explicit configuration input
	if err != nil {
		fail("read enc key: " + err.Error())
	}
	s := strings.TrimSpace(string(data))
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		fail("decode enc key: " + err.Error())
	}
	if len(key) != 32 {
		fail("enc key must decode to 32 bytes")
	}
	return key
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fail(name + " not set")
	}
	return v
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "lmdm-user:", msg)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, `lmdm-user <subcommand> [args]
  create-admin --email <addr>
  list
  reset-password <email>
  deactivate <email>
  unlock <email>

Env:
  LMDM_PG_DSN        postgres connection string
  LMDM_ENC_KEY_PATH  path to AES-256 master key (base64, produced by lmdm-keygen) — required for create-admin`)
}
