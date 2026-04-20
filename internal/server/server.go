// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package server wires together the HTTP and gRPC listeners with a clean
// shutdown path.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

// Server owns the HTTP and gRPC servers and their lifecycle.
type Server struct {
	httpSrv *http.Server
	grpcSrv *grpc.Server
	grpcLis net.Listener
	tlsCfg  *tls.Config
}

// New creates a Server bound to the given addresses. It does not start
// listening until Start is called. When tlsConfig is non-nil both the HTTP
// and gRPC listeners terminate TLS with the provided config; passing nil
// keeps the servers plaintext (used by tests and local dev).
func New(httpAddr, grpcAddr string, httpHandler http.Handler, tlsConfig *tls.Config) (*Server, error) {
	var grpcSrv *grpc.Server
	if tlsConfig != nil {
		grpcSrv = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		grpcSrv = grpc.NewServer()
	}
	reflection.Register(grpcSrv) // aids debugging; real services will be registered later

	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return nil, fmt.Errorf("server: listen grpc %s: %w", grpcAddr, err)
	}

	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
	}
	return &Server{httpSrv: httpSrv, grpcSrv: grpcSrv, grpcLis: grpcLis, tlsCfg: tlsConfig}, nil
}

// GRPC exposes the gRPC server so future plans can register services on it.
func (s *Server) GRPC() *grpc.Server { return s.grpcSrv }

// Start runs both servers in background goroutines. The returned channel
// receives the first fatal error from either server, if any. HTTP and gRPC
// are served over TLS when the Server was constructed with a tls.Config.
func (s *Server) Start() <-chan error {
	errs := make(chan error, 2)
	go func() {
		if err := s.grpcSrv.Serve(s.grpcLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errs <- fmt.Errorf("grpc: %w", err)
		}
	}()
	go func() {
		var err error
		if s.tlsCfg != nil {
			// Cert/key are already in TLSConfig.Certificates — the empty
			// strings tell net/http to reuse them.
			err = s.httpSrv.ListenAndServeTLS("", "")
		} else {
			err = s.httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("http: %w", err)
		}
	}()
	return errs
}

// Shutdown stops both servers, giving up to `timeout` for in-flight requests.
func (s *Server) Shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var first error
	if err := s.httpSrv.Shutdown(ctx); err != nil {
		first = err
	}

	done := make(chan struct{})
	go func() {
		s.grpcSrv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.grpcSrv.Stop()
	}
	return first
}
