// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package tlspki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRevocationCache_AddHasReplace_RoundTrip(t *testing.T) {
	c := NewRevocationCache()

	c.Add("serial-A")
	if !c.Has("serial-A") {
		t.Fatalf("expected serial-A to be present after Add")
	}
	if c.Has("serial-Z") {
		t.Fatalf("expected serial-Z to be absent")
	}

	c.Replace([]string{"serial-B", "serial-C"})
	if c.Has("serial-A") {
		t.Fatalf("expected serial-A to be gone after Replace")
	}
	if !c.Has("serial-B") {
		t.Fatalf("expected serial-B to be present after Replace")
	}
	if !c.Has("serial-C") {
		t.Fatalf("expected serial-C to be present after Replace")
	}
}

// signedClientCert mints a cert via the CA helpers and parses it for use as a
// peer certificate in verifiedChains.
func signedClientCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	ca := newTestCA(t)
	csrDER, _ := makeCSR(t, cn)
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	certPEM, err := ca.SignCSR(csr, cn, 0)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		t.Fatalf("decode signed cert")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}
	return cert
}

func TestRevocationCache_VerifyPeerCertificate_PassesWhenNotRevoked(t *testing.T) {
	cert := signedClientCert(t, "device-pass")
	c := NewRevocationCache()

	chains := [][]*x509.Certificate{{cert}}
	if err := c.VerifyPeerCertificate(nil, chains); err != nil {
		t.Fatalf("expected nil error for non-revoked peer, got: %v", err)
	}
}

func TestRevocationCache_VerifyPeerCertificate_RejectsRevoked(t *testing.T) {
	cert := signedClientCert(t, "device-revoked")
	c := NewRevocationCache()
	c.Add(cert.SerialNumber.String())

	chains := [][]*x509.Certificate{{cert}}
	err := c.VerifyPeerCertificate(nil, chains)
	if err == nil {
		t.Fatalf("expected error for revoked peer")
	}
	if !errors.Is(err, ErrCertificateRevoked) {
		t.Fatalf("expected ErrCertificateRevoked, got: %v", err)
	}
}

func TestRevocationCache_VerifyPeerCertificate_NoChain_Errors(t *testing.T) {
	c := NewRevocationCache()
	err := c.VerifyPeerCertificate(nil, nil)
	if err == nil {
		t.Fatalf("expected error for missing verified chain")
	}
	if !strings.Contains(err.Error(), "no verified chain") {
		t.Fatalf("expected 'no verified chain' error, got: %v", err)
	}
}

func TestRevocationCache_ConcurrentAddHas(t *testing.T) {
	c := NewRevocationCache()
	const writers = 10
	const readers = 10
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	for i := 0; i < writers; i++ {
		id := i
		go func() {
			defer wg.Done()
			n := 0
			for {
				select {
				case <-done:
					return
				default:
					c.Add(serialFor(id, n))
					n++
				}
			}
		}()
	}
	for i := 0; i < readers; i++ {
		id := i
		go func() {
			defer wg.Done()
			n := 0
			for {
				select {
				case <-done:
					return
				default:
					_ = c.Has(serialFor(id, n))
					n++
				}
			}
		}()
	}

	time.Sleep(100 * time.Millisecond)
	close(done)
	wg.Wait()
}

// workerLetters indexes a small letter set for serialFor without needing an
// int->byte conversion that gosec G115 would flag.
const workerLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func serialFor(worker, n int) string {
	// worker is bounded to [0, writers+readers); index defensively.
	idx := worker % len(workerLetters)
	return workerLetters[idx:idx+1] + ":" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
