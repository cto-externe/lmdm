// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"os"
	"path/filepath"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func TestReadDMIMapTrimsTrailingNewlines(t *testing.T) {
	dir := t.TempDir()
	writes := map[string]string{
		"sys_vendor":     "Dell Inc.\n",
		"product_name":   "Latitude 7440",
		"product_serial": "ABC123\n",
		"chassis_type":   "10\n",
		"bios_vendor":    "Dell Inc.",
		"bios_version":   "1.7.0\n",
		"bios_date":      "04/14/2024\n",
	}
	for name, content := range writes {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := readDMIMap(dir)

	if m["sys_vendor"] != "Dell Inc." {
		t.Errorf("sys_vendor = %q", m["sys_vendor"])
	}
	if m["bios_date"] != "04/14/2024" {
		t.Errorf("bios_date = %q (trailing newline not trimmed)", m["bios_date"])
	}
}

func TestNormalizeDMIStripsOEMPlaceholders(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Legit values pass through.
		{"Dell Inc.", "Dell Inc."},
		{"Latitude 7440", "Latitude 7440"},
		{"ABC123", "ABC123"},
		// Empty / whitespace.
		{"", ""},
		{"   ", ""},
		// Known OEM placeholders (case-insensitive).
		{"To Be Filled By O.E.M.", ""},
		{"to be filled by o.e.m.", ""},
		{"Default string", ""},
		{"System manufacturer", ""},
		{"System Product Name", ""},
		{"System Version", ""},
		{"Not Specified", ""},
		{"Not Applicable", ""},
		{"N/A", ""},
		{"None", ""},
		{"0", ""},
	}
	for _, c := range cases {
		got := normalizeDMI(c.in)
		if got != c.want {
			t.Errorf("normalizeDMI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDMIMapToSystemAndBIOS(t *testing.T) {
	m := map[string]string{
		"sys_vendor":     "Dell Inc.",
		"product_name":   "Latitude 7440",
		"product_serial": "ABC123",
		"chassis_type":   "10", // notebook
		"bios_vendor":    "Dell Inc.",
		"bios_version":   "1.7.0",
		"bios_date":      "04/14/2024",
	}
	sys := dmiToSystemInfo(m)
	if sys.Manufacturer != "Dell Inc." || sys.Model != "Latitude 7440" || sys.SerialNumber != "ABC123" {
		t.Errorf("SystemInfo = %+v", sys)
	}
	if sys.FormFactor != "laptop" {
		t.Errorf("FormFactor = %q, want laptop", sys.FormFactor)
	}

	bios := dmiToBIOSInfo(m)
	if bios.Vendor != "Dell Inc." || bios.Version != "1.7.0" || bios.Date != "04/14/2024" {
		t.Errorf("BIOSInfo = %+v", bios)
	}
}

func TestDMIMapStripsOEMNoise(t *testing.T) {
	// Typical reconditioned / budget / VM hardware: multiple OEM placeholders.
	m := map[string]string{
		"sys_vendor":     "System manufacturer",
		"product_name":   "To Be Filled By O.E.M.",
		"product_serial": "Default string",
		"chassis_type":   "3",
		"bios_vendor":    "Dell Inc.",
		"bios_version":   "1.7.0",
		"bios_date":      "Not Specified",
	}
	sys := dmiToSystemInfo(m)
	if sys.Manufacturer != "" || sys.Model != "" || sys.SerialNumber != "" {
		t.Errorf("OEM noise leaked: %+v", sys)
	}
	if sys.FormFactor != "desktop" {
		t.Errorf("FormFactor = %q (chassis_type should still be honored)", sys.FormFactor)
	}
	bios := dmiToBIOSInfo(m)
	if bios.Vendor != "Dell Inc." || bios.Version != "1.7.0" {
		t.Errorf("legit BIOS fields dropped: %+v", bios)
	}
	if bios.Date != "" {
		t.Errorf("Date should be normalized from 'Not Specified' to empty, got %q", bios.Date)
	}
}

func TestChassisFormFactor(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{"3", "desktop"},
		{"9", "laptop"},
		{"10", "laptop"},
		{"14", "laptop"},
		{"1", "unknown"},
		{"", "unknown"},
		{"bogus", "unknown"},
	}
	for _, c := range cases {
		got := chassisFormFactor(c.code)
		if got != c.want {
			t.Errorf("chassisFormFactor(%q) = %q, want %q", c.code, got, c.want)
		}
	}
}

// Compile-time assertion that dmi.go uses lmdmv1 types.
var _ *lmdmv1.SystemInfo = (*lmdmv1.SystemInfo)(nil)
