// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agentinventory collects hardware, software and network inventory
// from the local system and builds an lmdmv1.InventoryReport.
//
// Each sub-collector exposes:
//   - A pure parse/transform function that is unit-tested with fixtures.
//   - A thin collect function that reads from the live system (/proc, /sys,
//     or os/exec) and feeds the parser.
//
// Collectors are independent and tolerant: a failure in one sub-collector
// yields empty/zero fields in the final InventoryReport, not an aborted
// collection. Optional hardware (TPM, battery) returns nil when absent —
// proto message-typed fields treat nil as "not set", which is what we want.
package agentinventory

import (
	"os"
	"path/filepath"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// dmiRoot is the kernel-exposed directory where DMI attributes live. Each
// attribute is a single-line text file.
const dmiRoot = "/sys/class/dmi/id"

// readDMIMap loads every readable DMI attribute from `root` into a map.
// Missing files are silently skipped (no root access → product_serial is
// typically unreadable and will just be absent). Values are TrimSpace'd.
// Use normalizeDMI() to additionally strip OEM placeholder strings when
// treating values as user-facing identifiers.
func readDMIMap(root string) map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, e.Name())) //nolint:gosec // reading from a fixed /sys subtree
		if err != nil {
			continue
		}
		out[e.Name()] = strings.TrimSpace(string(data))
	}
	return out
}

// oemPlaceholders lists values that OEMs, VM vendors, and default firmware
// templates commonly leave in DMI fields — meaningless strings that we do
// not want to surface in inventory. Compared case-insensitively.
var oemPlaceholders = map[string]struct{}{
	"to be filled by o.e.m.": {},
	"default string":         {},
	"system manufacturer":    {},
	"system product name":    {},
	"system version":         {},
	"not specified":          {},
	"not applicable":         {},
	"n/a":                    {},
	"none":                   {},
	"0":                      {},
}

// normalizeDMI trims the input and returns an empty string for known OEM
// placeholders. Use it on identifier-like DMI fields (manufacturer, model,
// serial, bios_date) before handing them to the proto message. Chassis type
// codes and bios_version are not normalized — chassis_type is numeric (no
// placeholder risk) and bios_version sometimes legitimately equals short
// identifiers like "1.0" that should not be stripped.
func normalizeDMI(val string) string {
	s := strings.TrimSpace(val)
	if s == "" {
		return ""
	}
	if _, blocked := oemPlaceholders[strings.ToLower(s)]; blocked {
		return ""
	}
	return s
}

// dmiToSystemInfo extracts the system-level hardware identity with OEM
// noise stripped.
func dmiToSystemInfo(m map[string]string) *lmdmv1.SystemInfo {
	return &lmdmv1.SystemInfo{
		Manufacturer: normalizeDMI(m["sys_vendor"]),
		Model:        normalizeDMI(m["product_name"]),
		SerialNumber: normalizeDMI(m["product_serial"]),
		FormFactor:   chassisFormFactor(m["chassis_type"]),
	}
}

// dmiToBIOSInfo extracts the BIOS/UEFI metadata with OEM noise stripped
// from the date field. Vendor and version stay as-is (versions like "1.7.0"
// are always legitimate, and BIOS vendors rarely hit the placeholder list).
func dmiToBIOSInfo(m map[string]string) *lmdmv1.BIOSInfo {
	return &lmdmv1.BIOSInfo{
		Vendor:  normalizeDMI(m["bios_vendor"]),
		Version: strings.TrimSpace(m["bios_version"]),
		Date:    normalizeDMI(m["bios_date"]),
	}
}

// chassisFormFactor maps the DMI chassis type code to the string form factor
// used in our proto. Codes from DMTF SMBIOS spec §7.4.1. Anything unmapped
// returns "unknown".
func chassisFormFactor(code string) string {
	switch code {
	case "3", "4", "5", "6", "7", "15", "16":
		return "desktop"
	case "8", "9", "10", "11", "12", "14", "18", "21":
		return "laptop"
	case "17", "23", "25", "28":
		return "server"
	case "13":
		return "all-in-one"
	case "30", "31", "32":
		return "tablet"
	default:
		return "unknown"
	}
}
