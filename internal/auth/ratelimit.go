// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"sync"
	"time"
)

// RateLimiter is a sliding-window counter keyed by an arbitrary string (typically client IP).
// Safe for concurrent use.
type RateLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	buckets map[string][]time.Time
}

// NewRateLimiter returns a limiter allowing at most max events per window per key.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{max: max, window: window, buckets: make(map[string][]time.Time)}
}

// Allow returns true if this event is admitted for key.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-r.window)
	arr := r.buckets[key]
	trimmed := arr[:0]
	for _, t := range arr {
		if t.After(cutoff) {
			trimmed = append(trimmed, t)
		}
	}
	if len(trimmed) >= r.max {
		r.buckets[key] = trimmed
		return false
	}
	r.buckets[key] = append(trimmed, now)
	return true
}
