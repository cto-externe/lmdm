// Package objectstore wraps the S3-compatible client used to talk to Garage.
// Keeping this in one place avoids scattering AWS SDK calls across the
// codebase and makes future backend swaps trivial.
package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Config describes how to reach a Garage (or any S3-compatible) endpoint.
type Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	PathStyle bool
}

// Client wraps an s3.Client with the configured bucket. Operations that need
// a bucket use the configured one — callers do not pass a bucket name.
type Client struct {
	s3     *s3.Client
	bucket string
}

// New builds a Client from Config.
func New(cfg Config) (*Client, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("objectstore: bucket is required")
	}
	awsCfg := aws.Config{
		Region: cfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			cfg.AccessKey, cfg.SecretKey, "",
		),
	}
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.PathStyle
	})
	return &Client{s3: s3Client, bucket: cfg.Bucket}, nil
}

// Bucket returns the configured bucket name.
func (c *Client) Bucket() string { return c.bucket }

// Put uploads an object at key with the given body.
func (c *Client) Put(ctx context.Context, key string, body io.Reader) error {
	_, err := c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
		Body:   body,
	})
	if err != nil {
		return fmt.Errorf("objectstore: put %s: %w", key, err)
	}
	return nil
}

// Get fetches an object by key. Caller closes the returned reader.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("objectstore: get %s: %w", key, err)
	}
	return out.Body, nil
}

// PresignGet returns a time-limited URL that lets a client fetch an object
// without credentials. 15 minutes is the default per spec §10.2.
func (c *Client) PresignGet(ctx context.Context, key string, ttl time.Duration) (string, error) {
	ps := s3.NewPresignClient(c.s3)
	req, err := ps.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &c.bucket,
		Key:    &key,
	}, func(o *s3.PresignOptions) { o.Expires = ttl })
	if err != nil {
		return "", fmt.Errorf("objectstore: presign %s: %w", key, err)
	}
	return req.URL, nil
}

// Ping verifies the configured bucket is reachable and accessible. Used by
// healthchecks: presigning is a local-only operation that doesn't actually
// touch the network, so we use HeadBucket instead.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.s3.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: &c.bucket,
	})
	if err != nil {
		return fmt.Errorf("objectstore: head bucket %s: %w", c.bucket, err)
	}
	return nil
}
