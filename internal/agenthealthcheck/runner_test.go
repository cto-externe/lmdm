// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// fakeCommandRunner is a deterministic agenthealth.CommandRunner used by tests.
// Behaviors are looked up by command name; a key is the joined "name args..."
// or just the binary name. The default response is empty stdout, exit 0.
type fakeCommandRunner struct {
	mu     sync.Mutex
	calls  []string
	stdout map[string][]byte
	exit   map[string]int
	err    map[string]error
}

func newFakeCommandRunner() *fakeCommandRunner {
	return &fakeCommandRunner{
		stdout: map[string][]byte{},
		exit:   map[string]int{},
		err:    map[string]error{},
	}
}

func (f *fakeCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	key := name
	if len(args) > 0 {
		key = name + " " + strings.Join(args, " ")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, key)
	return f.stdout[key], f.exit[key], f.err[key]
}

func (f *fakeCommandRunner) callsCopy() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

// fakeNATSProber is a stub NATSAckProber.
type fakeNATSProber struct {
	err error
}

func (f *fakeNATSProber) AckProbe(_ context.Context) error { return f.err }

func TestRunner_Run_DispatchesByType(t *testing.T) {
	// HTTP server that returns 200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Read our own (truncated) comm so the ProcessCheck dispatch has a target
	// that actually exists in /proc, regardless of the test binary name.
	commBytes, err := os.ReadFile(filepath.Join("/proc", "self", "comm"))
	if err != nil {
		t.Skipf("/proc not available: %v", err)
	}
	selfComm := strings.TrimSpace(string(commBytes))

	cmd := newFakeCommandRunner()
	cmd.stdout["systemctl is-active myservice"] = []byte("active\n")
	cmd.exit["systemctl is-active myservice"] = 0
	cmd.stdout["sh -c true"] = []byte("")
	cmd.exit["sh -c true"] = 0

	checks := []*lmdmv1.HealthCheckDefinition{
		{
			Name:           "http-check",
			TimeoutSeconds: 5,
			Check:          &lmdmv1.HealthCheckDefinition_HttpGet{HttpGet: &lmdmv1.HTTPGetCheck{Url: srv.URL, ExpectedStatus: 200}},
		},
		{
			Name:           "tcp-check",
			TimeoutSeconds: 5,
			Check:          &lmdmv1.HealthCheckDefinition_TcpConnect{TcpConnect: &lmdmv1.TCPConnectCheck{Host: host, Port: uint32(port)}},
		},
		{
			Name:  "process-check",
			Check: &lmdmv1.HealthCheckDefinition_ProcessCheck{ProcessCheck: &lmdmv1.ProcessCheck{ProcessName: selfComm}},
		},
		{
			Name:           "service-check",
			TimeoutSeconds: 5,
			Check:          &lmdmv1.HealthCheckDefinition_ServiceCheck{ServiceCheck: &lmdmv1.ServiceCheck{ServiceName: "myservice", ExpectedState: "active"}},
		},
		{
			Name:           "command-check",
			TimeoutSeconds: 5,
			Check:          &lmdmv1.HealthCheckDefinition_CommandCheck{CommandCheck: &lmdmv1.CommandCheck{Command: "true", ExpectedExit: 0}},
		},
	}

	r := NewRunner(nil, cmd)
	results := r.Run(context.Background(), checks)
	if len(results) != 5 {
		t.Fatalf("want 5 results, got %d", len(results))
	}
	for i, res := range results {
		if !res.Passed {
			t.Errorf("check %d (%s) not passed: %s", i, res.Name, res.Detail)
		}
	}

	// confirm fake runner saw both systemctl + sh invocations
	calls := cmd.callsCopy()
	sawSystemctl := false
	sawSh := false
	for _, c := range calls {
		if strings.HasPrefix(c, "systemctl is-active myservice") {
			sawSystemctl = true
		}
		if strings.HasPrefix(c, "sh -c true") {
			sawSh = true
		}
	}
	if !sawSystemctl || !sawSh {
		t.Errorf("dispatch did not call systemctl/sh: %v", calls)
	}
}

func TestRunner_Run_UnknownType_ReturnsFailedResult(t *testing.T) {
	r := NewRunner(nil, nil)
	res := r.Run(context.Background(), []*lmdmv1.HealthCheckDefinition{
		{Name: "no-oneof"},
	})
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if res[0].Passed {
		t.Errorf("want failed for unknown type")
	}
	if res[0].Detail != "unknown check type" {
		t.Errorf("want 'unknown check type', got %q", res[0].Detail)
	}
}

func TestRunner_Run_NilCheck_ReturnsFailedResult(t *testing.T) {
	r := NewRunner(nil, nil)
	res := r.Run(context.Background(), []*lmdmv1.HealthCheckDefinition{nil})
	if len(res) != 1 || res[0].Passed {
		t.Fatalf("want failed result, got %+v", res)
	}
}

func TestRunner_RunBuiltins_Returns4Results(t *testing.T) {
	cmd := newFakeCommandRunner()
	// dbus = active
	cmd.stdout["systemctl is-active dbus"] = []byte("active\n")
	cmd.exit["systemctl is-active dbus"] = 0
	// systemd-networkd = active (so networking passes on first try)
	cmd.stdout["systemctl is-active systemd-networkd"] = []byte("active\n")
	cmd.exit["systemctl is-active systemd-networkd"] = 0
	// ssh = active
	cmd.stdout["systemctl is-active ssh"] = []byte("active\n")
	cmd.exit["systemctl is-active ssh"] = 0

	r := NewRunner(&fakeNATSProber{}, cmd)
	res := r.RunBuiltins(context.Background())
	if len(res) != 4 {
		t.Fatalf("want 4 results, got %d", len(res))
	}
	wantNames := []string{
		"system.nats_reachable",
		"system.dbus_active",
		"system.networking_active",
		"system.ssh_active",
	}
	for i, n := range wantNames {
		if res[i].Name != n {
			t.Errorf("result[%d] name: want %q got %q", i, n, res[i].Name)
		}
		if !res[i].Passed {
			t.Errorf("result[%d] (%s) not passed: %s", i, res[i].Name, res[i].Detail)
		}
	}
}

func TestRunner_RunBuiltins_NATSProberError(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.stdout["systemctl is-active dbus"] = []byte("active\n")
	cmd.stdout["systemctl is-active systemd-networkd"] = []byte("active\n")
	cmd.stdout["systemctl is-active ssh"] = []byte("active\n")

	r := NewRunner(&fakeNATSProber{err: errors.New("no jetstream")}, cmd)
	res := r.RunBuiltins(context.Background())
	if res[0].Passed {
		t.Errorf("want nats_reachable failed when prober errors")
	}
	if !strings.Contains(res[0].Detail, "no jetstream") {
		t.Errorf("want detail to include error message, got %q", res[0].Detail)
	}
}
