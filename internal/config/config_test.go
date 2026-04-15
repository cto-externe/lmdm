package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("Load with empty env: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr default = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.GRPCAddr != ":50051" {
		t.Errorf("GRPCAddr default = %q, want :50051", cfg.GRPCAddr)
	}
	if cfg.DatabaseURL == "" {
		t.Error("DatabaseURL must have a default for local dev")
	}
	if cfg.NATSURL == "" {
		t.Error("NATSURL must have a default for local dev")
	}
	if cfg.ServerKeyPath == "" {
		t.Error("ServerKeyPath must have a default")
	}
	if cfg.EnrollmentCertTTL == 0 {
		t.Error("EnrollmentCertTTL must have a default")
	}
}

func TestLoadOverrides(t *testing.T) {
	env := map[string]string{ //nolint:gosec // test fixture, not a real credential
		"LMDM_HTTP_ADDR":    ":9090",
		"LMDM_GRPC_ADDR":    ":50052",
		"LMDM_DATABASE_URL": "postgres://user:pass@host:5432/lmdm",
		"LMDM_NATS_URL":     "nats://nats.example.com:4222",
		"LMDM_S3_ENDPOINT":  "https://s3.example.com",
		"LMDM_S3_BUCKET":    "lmdm-packages",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":9090" || cfg.GRPCAddr != ":50052" {
		t.Errorf("addresses not overridden: %+v", cfg)
	}
	if cfg.DatabaseURL != env["LMDM_DATABASE_URL"] {
		t.Errorf("DatabaseURL = %q", cfg.DatabaseURL)
	}
	if cfg.S3Bucket != "lmdm-packages" {
		t.Errorf("S3Bucket = %q", cfg.S3Bucket)
	}
}

func TestLoadEnrollmentOverrides(t *testing.T) {
	env := map[string]string{
		"LMDM_SERVER_KEY_PATH":     "/tmp/key.bin",
		"LMDM_ENROLLMENT_CERT_TTL": "168h",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerKeyPath != "/tmp/key.bin" {
		t.Errorf("ServerKeyPath = %q", cfg.ServerKeyPath)
	}
	if cfg.EnrollmentCertTTL != 7*24*time.Hour {
		t.Errorf("EnrollmentCertTTL = %v", cfg.EnrollmentCertTTL)
	}
}
