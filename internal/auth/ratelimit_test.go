// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if rl.Allow("1.2.3.4") {
		t.Error("4th request must be blocked")
	}
}

func TestRateLimiter_SeparateKeysIndependent(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	if !rl.Allow("a") {
		t.Fatal()
	}
	if !rl.Allow("b") {
		t.Fatal("independent key should be allowed")
	}
}

func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	rl := NewRateLimiter(1, 20*time.Millisecond)
	_ = rl.Allow("x")
	if rl.Allow("x") {
		t.Fatal("second call within window should fail")
	}
	time.Sleep(30 * time.Millisecond)
	if !rl.Allow("x") {
		t.Error("should be allowed after window expiry")
	}
}
