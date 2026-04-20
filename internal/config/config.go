// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package config loads runtime configuration from environment variables.
// For local development, sensible defaults point at the docker-compose stack.
package config

import (
	"strconv"
	"time"
)

// Config holds the runtime configuration for the LMDM server.
type Config struct {
	HTTPAddr          string
	GRPCAddr          string
	DatabaseURL       string
	NATSURL           string
	S3Endpoint        string
	S3Region          string
	S3Bucket          string
	S3AccessKey       string
	S3SecretKey       string
	// ServerSigningKeyPath points at the pqhybrid (Ed25519 + ML-DSA-65)
	// signing key used by the control plane to sign AgentIdentityCert and
	// profile bundles. Configured via LMDM_SERVER_SIGNING_KEY_PATH.
	ServerSigningKeyPath string
	EnrollmentCertTTL    time.Duration

	// JWTPrivateKeyPath points at a PEM-encoded ECDSA P-256 key loaded at
	// startup by auth.LoadJWTSigner. Required in production; falls back to
	// the repo-local deploy/secrets path for dev convenience.
	JWTPrivateKeyPath string
	// EncKeyPath points at a base64 file holding the 32-byte AES-256 master
	// key used by internal/auth to seal TOTP secrets at rest.
	EncKeyPath string

	// HealthRetentionDays is the retention window applied by the health
	// snapshots pruner. Default 90. Configured via LMDM_HEALTH_RETENTION_DAYS.
	HealthRetentionDays int

	// CACertPath / CAKeyPath point at the LMDM Root CA material used to
	// verify agent client certificates and sign enrollment CSRs. The server
	// fails fast at startup if either file is missing.
	CACertPath string
	CAKeyPath  string
	// ServerCertPath / ServerKeyPath point at the server's TLS leaf cert
	// (signed by the CA) and its private key, loaded into tls.Config.
	ServerCertPath string
	ServerKeyPath  string
}

// EnvLookup is the minimal interface required to read an environment variable.
// Kept as a function type so tests can inject a map-backed lookup without
// touching process env.
type EnvLookup func(key string) string

// Load builds a Config from the given env lookup, applying dev-friendly
// defaults for local docker-compose usage.
func Load(env EnvLookup) (*Config, error) {
	cfg := &Config{
		HTTPAddr:            firstNonEmpty(env("LMDM_HTTP_ADDR"), ":8080"),
		GRPCAddr:            firstNonEmpty(env("LMDM_GRPC_ADDR"), ":50051"),
		DatabaseURL:         firstNonEmpty(env("LMDM_DATABASE_URL"), "postgres://lmdm:lmdm@localhost:5432/lmdm?sslmode=disable"),
		NATSURL:             firstNonEmpty(env("LMDM_NATS_URL"), "nats://localhost:4222"),
		S3Endpoint:          firstNonEmpty(env("LMDM_S3_ENDPOINT"), "http://localhost:3900"),
		S3Region:            firstNonEmpty(env("LMDM_S3_REGION"), "garage"),
		S3Bucket:            firstNonEmpty(env("LMDM_S3_BUCKET"), "lmdm-packages"),
		S3AccessKey:         env("LMDM_S3_ACCESS_KEY"),
		S3SecretKey:         env("LMDM_S3_SECRET_KEY"),
		ServerSigningKeyPath: firstNonEmpty(env("LMDM_SERVER_SIGNING_KEY_PATH"), "/var/lib/lmdm/server-signing.key"),
		EnrollmentCertTTL:    parseDurationOrDefault(env("LMDM_ENROLLMENT_CERT_TTL"), 365*24*time.Hour),
		JWTPrivateKeyPath:    firstNonEmpty(env("LMDM_JWT_PRIVATE_KEY_PATH"), "deploy/secrets/jwt-priv.pem"),
		EncKeyPath:           firstNonEmpty(env("LMDM_ENC_KEY_PATH"), "deploy/secrets/enc-key.b64"),
		HealthRetentionDays:  parseIntOrDefault(env("LMDM_HEALTH_RETENTION_DAYS"), 90),
		CACertPath:           firstNonEmpty(env("LMDM_CA_CERT_PATH"), "deploy/secrets/ca.crt"),
		CAKeyPath:            firstNonEmpty(env("LMDM_CA_KEY_PATH"), "deploy/secrets/ca.key"),
		ServerCertPath:       firstNonEmpty(env("LMDM_SERVER_CERT_PATH"), "deploy/secrets/server.crt"),
		ServerKeyPath:        firstNonEmpty(env("LMDM_SERVER_KEY_PATH"), "deploy/secrets/server.key"),
	}
	return cfg, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

func parseIntOrDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
