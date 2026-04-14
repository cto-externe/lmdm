package objectstore

import (
	"testing"
)

func TestNewClientConfig(t *testing.T) {
	c, err := New(Config{
		Endpoint:   "http://localhost:3900",
		Region:     "garage",
		Bucket:     "lmdm-packages",
		AccessKey:  "test",
		SecretKey:  "test",
		PathStyle:  true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Bucket() != "lmdm-packages" {
		t.Errorf("Bucket() = %q", c.Bucket())
	}
}

func TestNewClientRejectsMissingBucket(t *testing.T) {
	_, err := New(Config{Endpoint: "http://localhost", Region: "garage"})
	if err == nil {
		t.Fatal("New must reject missing bucket")
	}
}
