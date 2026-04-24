// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package ratelimit provides a minimal in-memory per-IP token bucket.
// Used to throttle /web/login. Not suitable for multi-instance deployments —
// replace with a Redis-backed impl when LMDM scales beyond single node.
package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter holds per-IP rate limiters.
type Limiter struct {
	mu       sync.Mutex
	per      rate.Limit
	burst    int
	ttl      time.Duration
	visitors map[string]*visitor
}

type visitor struct {
	lim  *rate.Limiter
	last time.Time
}

// New creates a limiter allowing `burst` requests per `window` per IP.
func New(burst int, window time.Duration) *Limiter {
	l := &Limiter{
		per:      rate.Every(window / time.Duration(burst)),
		burst:    burst,
		ttl:      window * 2,
		visitors: map[string]*visitor{},
	}
	go l.gcLoop()
	return l
}

// Protect wraps next with per-IP rate limiting.
func (l *Limiter) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !l.allow(ip) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *Limiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.visitors[ip]
	if !ok {
		v = &visitor{lim: rate.NewLimiter(l.per, l.burst)}
		l.visitors[ip] = v
	}
	v.last = time.Now()
	return v.lim.Allow()
}

// gcLoop evicts stale visitors every minute.
func (l *Limiter) gcLoop() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		cutoff := time.Now().Add(-l.ttl)
		l.mu.Lock()
		for ip, v := range l.visitors {
			if v.last.Before(cutoff) {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}
