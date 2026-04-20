// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenttls

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"time"
)

// RenewThreshold is how close to expiry we start trying to renew.
const RenewThreshold = 30 * 24 * time.Hour

// CheckInterval is how often Run ticks.
const CheckInterval = 24 * time.Hour

// RenewClient abstracts the gRPC RenewCertificate RPC so tests can inject a fake.
type RenewClient interface {
	RenewCertificate(ctx context.Context, csrPEM []byte) (newCertPEM []byte, err error)
}

// Runner ticks daily, checks the stored cert's NotAfter, and if it's within
// RenewThreshold, generates a fresh keypair + CSR and calls RenewClient.
// On success, persists the new cert + key atomically via store.SaveCredentials.
// On failure, logs WARN and retries at the next tick.
type Runner struct {
	store    *Store
	client   RenewClient
	deviceID string
	hostname string
	interval time.Duration
}

// NewRunner wires a renewal runner. interval defaults to CheckInterval when 0.
func NewRunner(store *Store, client RenewClient, deviceID, hostname string) *Runner {
	return &Runner{
		store:    store,
		client:   client,
		deviceID: deviceID,
		hostname: hostname,
		interval: CheckInterval,
	}
}

// WithInterval is used by tests to shorten the ticker.
func (r *Runner) WithInterval(d time.Duration) *Runner {
	r.interval = d
	return r
}

// Run blocks until ctx cancel. Checks at startup and every interval.
// Returns nil on ctx cancel.
func (r *Runner) Run(ctx context.Context) error {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	r.tryRenewOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.tryRenewOnce(ctx)
		}
	}
}

// tryRenewOnce performs one check + renew attempt. Exported-ish for tests via
// unexported name (same-package test access).
func (r *Runner) tryRenewOnce(ctx context.Context) {
	certPEM, _, caPEM, err := r.store.LoadCredentials()
	if err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return
		}
		slog.Warn("agenttls: load creds for renew check failed", "err", err)
		return
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		slog.Warn("agenttls: cert pem decode failed")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		slog.Warn("agenttls: parse cert failed", "err", err)
		return
	}
	if time.Until(cert.NotAfter) > RenewThreshold {
		return
	}
	slog.Info("agenttls: renewing certificate", "not_after", cert.NotAfter)
	newKeypair, err := GenerateKeypair()
	if err != nil {
		slog.Warn("agenttls: generate keypair for renew failed", "err", err)
		return
	}
	csr, err := newKeypair.BuildCSR(r.deviceID, r.hostname)
	if err != nil {
		slog.Warn("agenttls: build csr for renew failed", "err", err)
		return
	}
	newCert, err := r.client.RenewCertificate(ctx, csr)
	if err != nil {
		slog.Warn("agenttls: renew rpc failed, will retry at next tick", "err", err)
		return
	}
	newKeyPEM, err := newKeypair.MarshalPrivateKeyPEM()
	if err != nil {
		slog.Warn("agenttls: marshal new key failed", "err", err)
		return
	}
	if err := r.store.SaveCredentials(newCert, newKeyPEM, caPEM); err != nil {
		slog.Error("agenttls: save renewed creds failed", "err", err)
		return
	}
	slog.Info("agenttls: certificate renewed successfully")
}
