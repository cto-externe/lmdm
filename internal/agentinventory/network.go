// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// ipAddrEntry mirrors a relevant subset of `ip -j addr` output.
type ipAddrEntry struct {
	IfName    string            `json:"ifname"`
	Address   string            `json:"address"`
	OperState string            `json:"operstate"`
	LinkType  string            `json:"link_type"`
	AddrInfo  []ipAddrInfoEntry `json:"addr_info"`
}

type ipAddrInfoEntry struct {
	Family    string `json:"family"` // "inet" | "inet6"
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}

// parseIPAddrJSON converts `ip -j addr` output to []NetworkInterface. For
// each interface we pick the first IPv4 address as Ipv4 and the first IPv6
// as Ipv6. Subnet is derived from the IPv4 prefix length.
func parseIPAddrJSON(data []byte) ([]*lmdmv1.NetworkInterface, error) {
	var raw []ipAddrEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("ip addr: %w", err)
	}
	out := make([]*lmdmv1.NetworkInterface, 0, len(raw))
	for _, e := range raw {
		iface := &lmdmv1.NetworkInterface{
			Name: e.IfName,
			Mac:  e.Address,
			Type: linkTypeToIfaceType(e.LinkType, e.IfName),
		}
		for _, ai := range e.AddrInfo {
			switch ai.Family {
			case "inet":
				if iface.Ipv4 == "" {
					iface.Ipv4 = ai.Local
					iface.Subnet = ipv4Subnet(ai.Local, ai.PrefixLen)
				}
			case "inet6":
				if iface.Ipv6 == "" {
					iface.Ipv6 = ai.Local
				}
			}
		}
		out = append(out, iface)
	}
	return out, nil
}

// ipv4Subnet naively masks the last (32-prefix)/8 octets to zero. Good enough
// for prefixes that are multiples of 8; for others we return the original/prefix
// notation without masking (the full inventory is advisory, not authoritative).
func ipv4Subnet(ip string, prefix int) string {
	if prefix%8 != 0 {
		return fmt.Sprintf("%s/%d", ip, prefix)
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	zeroFrom := prefix / 8
	for i := zeroFrom; i < 4; i++ {
		parts[i] = "0"
	}
	return fmt.Sprintf("%s/%d", strings.Join(parts, "."), prefix)
}

func linkTypeToIfaceType(linkType, name string) string {
	switch linkType {
	case "ether":
		if strings.HasPrefix(name, "wl") || strings.HasPrefix(name, "wlan") {
			return "wifi"
		}
		return "ethernet"
	case "loopback":
		return "loopback"
	}
	// Cellular shows up via linkType="none" + ifname pattern; skip auto-detect.
	return ""
}

// ipRouteEntry mirrors `ip -j route show default`.
type ipRouteEntry struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

// parseDefaultRouteJSON returns (interfaceName, gatewayIP). Returns empty
// strings (no error) when the input is `[]` (no default route).
func parseDefaultRouteJSON(data []byte) (string, string, error) {
	var raw []ipRouteEntry
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", "", fmt.Errorf("ip route: %w", err)
	}
	if len(raw) == 0 {
		return "", "", nil
	}
	return raw[0].Dev, raw[0].Gateway, nil
}

// parseResolvConf extracts nameservers, search domains, and domain from a
// /etc/resolv.conf stream. Lines starting with `#` or `;` are ignored.
func parseResolvConf(r io.Reader) (servers []string, domain string, search []string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			servers = append(servers, fields[1])
		case "domain":
			domain = fields[1]
		case "search":
			search = append(search, fields[1:]...)
		}
	}
	return servers, domain, search
}
