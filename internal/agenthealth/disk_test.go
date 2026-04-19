// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealth

import (
	"context"
	"os"
	"testing"
)

// fakeCommandRunner returns canned fixtures keyed by command + space-joined
// args. It is shared by every collector test in this package.
type fakeCommandRunner struct {
	fixtures  map[string][]byte
	exitCodes map[string]int
}

func (f fakeCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, int, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if out, ok := f.fixtures[key]; ok {
		exit := f.exitCodes[key]
		return out, exit, nil
	}
	return nil, 0, os.ErrNotExist
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCollectSMART_Healthy_ParsesCriticalIDs(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"smartctl -j -a /dev/sda": loadFixture(t, "smartctl-sata-healthy.json"),
		},
	}
	dh, err := collectSMART(context.Background(), runner, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if !dh.SmartPassed {
		t.Error("expected smart_passed true on healthy fixture")
	}
	if dh.SataAttributes.ReallocatedSectors != 0 {
		t.Errorf("expected 0 reallocated, got %d", dh.SataAttributes.ReallocatedSectors)
	}
}

func TestCollectSMART_Reallocated_DetectsAttribute(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"smartctl -j -a /dev/sda": loadFixture(t, "smartctl-sata-reallocated.json"),
		},
	}
	dh, err := collectSMART(context.Background(), runner, "/dev/sda")
	if err != nil {
		t.Fatal(err)
	}
	if dh.SataAttributes.ReallocatedSectors == 0 {
		t.Fatal("expected non-zero reallocated sectors on reallocated fixture")
	}
}

func TestCollectSMART_ToleratesNonZeroInformationalExit(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures:  map[string][]byte{"smartctl -j -a /dev/sda": loadFixture(t, "smartctl-sata-healthy.json")},
		exitCodes: map[string]int{"smartctl -j -a /dev/sda": smartExitBitLogged | smartExitBitFailingPast},
	}
	if _, err := collectSMART(context.Background(), runner, "/dev/sda"); err != nil {
		t.Errorf("informational exit bits must not be fatal, got %v", err)
	}
}

func TestCollectSMART_FailsOnFatalExitBits(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures:  map[string][]byte{"smartctl -j -a /dev/sda": loadFixture(t, "smartctl-sata-healthy.json")},
		exitCodes: map[string]int{"smartctl -j -a /dev/sda": smartExitBitDeviceOpenFail},
	}
	if _, err := collectSMART(context.Background(), runner, "/dev/sda"); err == nil {
		t.Error("expected error on fatal exit bit (device open fail)")
	}
}

func TestCollectNVMe_Healthy(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"nvme smart-log /dev/nvme0n1 -o json": loadFixture(t, "nvme-smart-log-healthy.json"),
		},
	}
	dh, err := collectNVMe(context.Background(), runner, "/dev/nvme0n1")
	if err != nil {
		t.Fatal(err)
	}
	if !dh.SmartPassed {
		t.Error("healthy fixture should have critical_warning == 0")
	}
	if dh.LifeRemainingPct > 100 {
		t.Errorf("life remaining capped at 100, got %d", dh.LifeRemainingPct)
	}
}

func TestCollectNVMe_Worn_DetectsPercentUsed(t *testing.T) {
	runner := fakeCommandRunner{
		fixtures: map[string][]byte{
			"nvme smart-log /dev/nvme0n1 -o json": loadFixture(t, "nvme-smart-log-worn.json"),
		},
	}
	dh, err := collectNVMe(context.Background(), runner, "/dev/nvme0n1")
	if err != nil {
		t.Fatal(err)
	}
	if dh.NvmeSmartLog.PercentageUsed < 80 {
		t.Errorf("worn fixture should have percent_used >= 80, got %d", dh.NvmeSmartLog.PercentageUsed)
	}
}
