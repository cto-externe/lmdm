// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentenroll

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// RenewClient holds a persistent mTLS gRPC connection used by the agenttls
// renewer to call RenewCertificate. Built once at agent startup from the
// stored X.509 credentials; survives across renewal cycles.
type RenewClient struct {
	conn   *grpc.ClientConn
	client lmdmv1.EnrollmentServiceClient
}

// NewRenewClient dials grpcAddr with mTLS using tlsConfig.
func NewRenewClient(grpcAddr string, tlsConfig *tls.Config) (*RenewClient, error) {
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("agentenroll: dial renew: %w", err)
	}
	return &RenewClient{conn: conn, client: lmdmv1.NewEnrollmentServiceClient(conn)}, nil
}

// RenewCertificate satisfies agenttls.RenewClient.
func (c *RenewClient) RenewCertificate(ctx context.Context, csrPEM []byte) ([]byte, error) {
	resp, err := c.client.RenewCertificate(ctx, &lmdmv1.RenewCertificateRequest{CsrPem: csrPEM})
	if err != nil {
		return nil, err
	}
	return resp.GetNewCertificate(), nil
}

// Close releases the underlying gRPC connection.
func (c *RenewClient) Close() error { return c.conn.Close() }
