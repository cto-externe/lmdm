// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"net"
	"strconv"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func TestCheckTCP_HappyPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	res := checkTCP(context.Background(), "t", &lmdmv1.TCPConnectCheck{Host: host, Port: uint32(port)}, 5)
	if !res.Passed {
		t.Fatalf("want passed: %s", res.Detail)
	}
}

func TestCheckTCP_ConnRefused(t *testing.T) {
	// pick a port nobody listens on by listening then closing
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close()
	res := checkTCP(context.Background(), "t", &lmdmv1.TCPConnectCheck{Host: host, Port: uint32(port)}, 1)
	if res.Passed {
		t.Fatalf("want failed when nothing listens")
	}
}
