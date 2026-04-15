// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"testing"
)

const lsblkFixture = `{
   "blockdevices": [
      {"name":"sda","model":"Samsung SSD 990 PRO","serial":"S7DMNS0W1","size":"1000204886016","type":"disk","tran":"nvme","rota":"0"},
      {"name":"sdb","model":"","serial":"","size":"500107862016","type":"disk","tran":"sata","rota":"1"},
      {"name":"sda1","model":null,"serial":null,"size":"536870912","type":"part","tran":null,"rota":"0"},
      {"name":"sr0","model":"virtual CD","serial":"","size":"0","type":"rom","tran":"sata","rota":"1"}
   ]
}`

func TestParseLsblkFiltersDisks(t *testing.T) {
	disks, err := parseLsblkJSON([]byte(lsblkFixture))
	if err != nil {
		t.Fatalf("parseLsblkJSON: %v", err)
	}
	// Only sda + sdb (type=disk) — sda1 (part) and sr0 (rom) excluded.
	if len(disks) != 2 {
		t.Fatalf("len(disks) = %d, want 2", len(disks))
	}
	if disks[0].Name != "sda" || disks[0].Model != "Samsung SSD 990 PRO" {
		t.Errorf("disk 0: %+v", disks[0])
	}
	// 1_000_204_886_016 / (1<<30) ≈ 931 GB
	if disks[0].SizeGb < 900 || disks[0].SizeGb > 1000 {
		t.Errorf("disks[0].SizeGb = %d, want ~931", disks[0].SizeGb)
	}
	if disks[0].Type != "ssd_nvme" || disks[0].Transport != "nvme" {
		t.Errorf("disks[0].Type/Transport = %s/%s", disks[0].Type, disks[0].Transport)
	}
	if disks[1].Type != "hdd" || disks[1].Transport != "sata" {
		t.Errorf("disks[1].Type = %s", disks[1].Type)
	}
}

func TestParseLsblkMalformedJSON(t *testing.T) {
	_, err := parseLsblkJSON([]byte("not json"))
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}
