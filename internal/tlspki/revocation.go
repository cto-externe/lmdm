// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package tlspki

import (
	"crypto/x509"
	"errors"
	"sync"
)

// RevocationCache is a thread-safe set of revoked serial numbers, refreshable
// from the authoritative repo and/or invalidated via a NATS broadcast.
type RevocationCache struct {
	mu      sync.RWMutex
	serials map[string]struct{}
}

// NewRevocationCache returns an empty cache.
func NewRevocationCache() *RevocationCache {
	return &RevocationCache{serials: make(map[string]struct{})}
}

// Replace swaps the entire cache contents atomically. Used by the periodic
// refresh loop that pulls from the DB.
func (c *RevocationCache) Replace(serials []string) {
	m := make(map[string]struct{}, len(serials))
	for _, s := range serials {
		m[s] = struct{}{}
	}
	c.mu.Lock()
	c.serials = m
	c.mu.Unlock()
}

// Add inserts a single serial. Used by the NATS broadcast handler when a new
// revocation happens on any node.
func (c *RevocationCache) Add(serial string) {
	c.mu.Lock()
	c.serials[serial] = struct{}{}
	c.mu.Unlock()
}

// Has reports whether the serial is revoked.
func (c *RevocationCache) Has(serial string) bool {
	c.mu.RLock()
	_, ok := c.serials[serial]
	c.mu.RUnlock()
	return ok
}

// ErrCertificateRevoked is returned by VerifyPeerCertificate when the peer's
// cert serial matches a revocation.
var ErrCertificateRevoked = errors.New("tlspki: peer certificate revoked")

// VerifyPeerCertificate returns whether the peer cert in verifiedChains is
// revoked. Suitable for tls.Config.VerifyPeerCertificate. Go has already
// validated the chain by this point (if ClientCAs is set) — we only reject
// based on the revocation cache.
func (c *RevocationCache) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return errors.New("tlspki: no verified chain")
	}
	peer := verifiedChains[0][0]
	if c.Has(peer.SerialNumber.String()) {
		return ErrCertificateRevoked
	}
	return nil
}
