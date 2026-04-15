// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"bufio"
	"io"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// parseOSRelease parses an /etc/os-release style KEY=VALUE file and returns
// an OSInfo. Kernel + secure_boot are populated separately by the collector
// (this function is read-only on the given reader).
func parseOSRelease(r io.Reader) *lmdmv1.OSInfo {
	kv := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
		kv[key] = val
	}
	return &lmdmv1.OSInfo{
		Family:   osFamilyFromIDs(kv["ID"], kv["ID_LIKE"]),
		Name:     kv["ID"],
		Version:  kv["VERSION_ID"],
		Codename: kv["VERSION_CODENAME"],
	}
}

// osFamilyFromIDs classifies the OS family from ID and ID_LIKE fields.
func osFamilyFromIDs(id, idLike string) lmdmv1.OSFamily {
	all := strings.ToLower(id + " " + idLike)
	words := strings.Fields(all)
	for _, w := range words {
		switch w {
		case "debian", "ubuntu", "mint":
			return lmdmv1.OSFamily_OS_FAMILY_DEBIAN
		case "rhel", "fedora", "centos", "almalinux", "rocky":
			return lmdmv1.OSFamily_OS_FAMILY_RHEL
		case "nixos":
			return lmdmv1.OSFamily_OS_FAMILY_NIXOS
		}
	}
	return lmdmv1.OSFamily_OS_FAMILY_UNSPECIFIED
}
