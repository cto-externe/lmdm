// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"errors"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func TestCheckService_HappyPath(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.stdout["systemctl is-active myunit"] = []byte("active\n")
	cmd.exit["systemctl is-active myunit"] = 0
	res := checkService(context.Background(), cmd, "s", &lmdmv1.ServiceCheck{ServiceName: "myunit", ExpectedState: "active"}, 5)
	if !res.Passed {
		t.Fatalf("want passed: %s", res.Detail)
	}
}

func TestCheckService_DefaultExpectedActive(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.stdout["systemctl is-active myunit"] = []byte("active\n")
	cmd.exit["systemctl is-active myunit"] = 0
	res := checkService(context.Background(), cmd, "s", &lmdmv1.ServiceCheck{ServiceName: "myunit"}, 5)
	if !res.Passed {
		t.Fatalf("want passed with default expected: %s", res.Detail)
	}
}

func TestCheckService_WrongState(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.stdout["systemctl is-active myunit"] = []byte("inactive\n")
	cmd.exit["systemctl is-active myunit"] = 3
	res := checkService(context.Background(), cmd, "s", &lmdmv1.ServiceCheck{ServiceName: "myunit", ExpectedState: "active"}, 5)
	if res.Passed {
		t.Fatalf("want failed when inactive")
	}
}

func TestCheckService_NilRunner(t *testing.T) {
	res := checkService(context.Background(), nil, "s", &lmdmv1.ServiceCheck{ServiceName: "u"}, 5)
	if res.Passed {
		t.Fatalf("want failed with nil runner")
	}
}

func TestCheckService_RunnerError(t *testing.T) {
	cmd := newFakeCommandRunner()
	cmd.err["systemctl is-active myunit"] = errors.New("not installed")
	res := checkService(context.Background(), cmd, "s", &lmdmv1.ServiceCheck{ServiceName: "myunit"}, 5)
	if res.Passed {
		t.Fatalf("want failed when systemctl errors")
	}
}
