// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package config loads runtime configuration from environment variables.
// For local development, sensible defaults point at the docker-compose stack.
package config

import "time"

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
	ServerKeyPath     string
	EnrollmentCertTTL time.Duration

	// JWTPrivateKeyPath points at a PEM-encoded ECDSA P-256 key loaded at
	// startup by auth.LoadJWTSigner. Required in production; falls back to
	// the repo-local deploy/secrets path for dev convenience.
	JWTPrivateKeyPath string
	// EncKeyPath points at a base64 file holding the 32-byte AES-256 master
	// key used by internal/auth to seal TOTP secrets at rest.
	EncKeyPath string
}

// EnvLookup is the minimal interface required to read an environment variable.
// Kept as a function type so tests can inject a map-backed lookup without
// touching process env.
type EnvLookup func(key string) string

// Load builds a Config from the given env lookup, applying dev-friendly
// defaults for local docker-compose usage.
func Load(env EnvLookup) (*Config, error) {
	cfg := &Config{
		HTTPAddr:          firstNonEmpty(env("LMDM_HTTP_ADDR"), ":8080"),
		GRPCAddr:          firstNonEmpty(env("LMDM_GRPC_ADDR"), ":50051"),
		DatabaseURL:       firstNonEmpty(env("LMDM_DATABASE_URL"), "postgres://lmdm:lmdm@localhost:5432/lmdm?sslmode=disable"),
		NATSURL:           firstNonEmpty(env("LMDM_NATS_URL"), "nats://localhost:4222"),
		S3Endpoint:        firstNonEmpty(env("LMDM_S3_ENDPOINT"), "http://localhost:3900"),
		S3Region:          firstNonEmpty(env("LMDM_S3_REGION"), "garage"),
		S3Bucket:          firstNonEmpty(env("LMDM_S3_BUCKET"), "lmdm-packages"),
		S3AccessKey:       env("LMDM_S3_ACCESS_KEY"),
		S3SecretKey:       env("LMDM_S3_SECRET_KEY"),
		ServerKeyPath:     firstNonEmpty(env("LMDM_SERVER_KEY_PATH"), "/var/lib/lmdm/server-signing.key"),
		EnrollmentCertTTL: parseDurationOrDefault(env("LMDM_ENROLLMENT_CERT_TTL"), 365*24*time.Hour),
		JWTPrivateKeyPath: firstNonEmpty(env("LMDM_JWT_PRIVATE_KEY_PATH"), "deploy/secrets/jwt-priv.pem"),
		EncKeyPath:        firstNonEmpty(env("LMDM_ENC_KEY_PATH"), "deploy/secrets/enc-key.b64"),
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
