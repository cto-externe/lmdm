// Package config loads runtime configuration from environment variables.
// For local development, sensible defaults point at the docker-compose stack.
package config

// Config holds the runtime configuration for the LMDM server.
type Config struct {
	HTTPAddr    string
	GRPCAddr    string
	DatabaseURL string
	NATSURL     string
	S3Endpoint  string
	S3Region    string
	S3Bucket    string
	S3AccessKey string
	S3SecretKey string
}

// EnvLookup is the minimal interface required to read an environment variable.
// Kept as a function type so tests can inject a map-backed lookup without
// touching process env.
type EnvLookup func(key string) string

// Load builds a Config from the given env lookup, applying dev-friendly
// defaults for local docker-compose usage.
func Load(env EnvLookup) (*Config, error) {
	cfg := &Config{
		HTTPAddr:    firstNonEmpty(env("LMDM_HTTP_ADDR"), ":8080"),
		GRPCAddr:    firstNonEmpty(env("LMDM_GRPC_ADDR"), ":50051"),
		DatabaseURL: firstNonEmpty(env("LMDM_DATABASE_URL"), "postgres://lmdm:lmdm@localhost:5432/lmdm?sslmode=disable"),
		NATSURL:     firstNonEmpty(env("LMDM_NATS_URL"), "nats://localhost:4222"),
		S3Endpoint:  firstNonEmpty(env("LMDM_S3_ENDPOINT"), "http://localhost:3900"),
		S3Region:    firstNonEmpty(env("LMDM_S3_REGION"), "garage"),
		S3Bucket:    firstNonEmpty(env("LMDM_S3_BUCKET"), "lmdm-packages"),
		S3AccessKey: env("LMDM_S3_ACCESS_KEY"),
		S3SecretKey: env("LMDM_S3_SECRET_KEY"),
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
