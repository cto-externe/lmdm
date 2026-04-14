// Package server wires together the HTTP and gRPC listeners with a clean
// shutdown path.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server owns the HTTP and gRPC servers and their lifecycle.
type Server struct {
	httpSrv *http.Server
	grpcSrv *grpc.Server
	grpcLis net.Listener
}

// New creates a Server bound to the given addresses. It does not start
// listening until Start is called.
func New(httpAddr, grpcAddr string, httpHandler http.Handler) (*Server, error) {
	grpcSrv := grpc.NewServer()
	reflection.Register(grpcSrv) // aids debugging; real services will be registered later

	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return nil, fmt.Errorf("server: listen grpc %s: %w", grpcAddr, err)
	}

	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return &Server{httpSrv: httpSrv, grpcSrv: grpcSrv, grpcLis: grpcLis}, nil
}

// GRPC exposes the gRPC server so future plans can register services on it.
func (s *Server) GRPC() *grpc.Server { return s.grpcSrv }

// Start runs both servers in background goroutines. The returned channel
// receives the first fatal error from either server, if any.
func (s *Server) Start() <-chan error {
	errs := make(chan error, 2)
	go func() {
		if err := s.grpcSrv.Serve(s.grpcLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errs <- fmt.Errorf("grpc: %w", err)
		}
	}()
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
