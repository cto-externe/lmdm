// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"strings"
	"testing"
)

// Representative `ip -j addr` output (trimmed).
const ipAddrFixture = `[
  {
    "ifname": "lo",
    "address": "00:00:00:00:00:00",
    "operstate": "UNKNOWN",
    "addr_info": [
      {"family": "inet", "local": "127.0.0.1", "prefixlen": 8}
    ]
  },
  {
    "ifname": "eth0",
    "address": "aa:bb:cc:dd:ee:ff",
    "operstate": "UP",
    "link_type": "ether",
    "addr_info": [
      {"family": "inet",  "local": "192.168.1.42", "prefixlen": 24},
      {"family": "inet6", "local": "fe80::1",      "prefixlen": 64}
    ]
  }
]`

// `ip -j route show default`
const ipRouteFixture = `[{"dst":"default","gateway":"192.168.1.1","dev":"eth0"}]`

const resolvConfFixture = `# generated
nameserver 1.1.1.1
nameserver 9.9.9.9
search example.com intranet.example
domain example.com
`

func TestParseIPAddrJSON(t *testing.T) {
	ifs, err := parseIPAddrJSON([]byte(ipAddrFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(ifs) != 2 {
		t.Fatalf("len(ifs) = %d, want 2", len(ifs))
	}
	eth0 := ifs[1]
	if eth0.Name != "eth0" || eth0.Mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("eth0 = %+v", eth0)
	}
	if eth0.Ipv4 != "192.168.1.42" {
		t.Errorf("eth0.Ipv4 = %q", eth0.Ipv4)
	}
	if eth0.Subnet != "192.168.1.0/24" {
		t.Errorf("eth0.Subnet = %q", eth0.Subnet)
	}
	if eth0.Ipv6 != "fe80::1" {
		t.Errorf("eth0.Ipv6 = %q", eth0.Ipv6)
	}
	if eth0.Type != "ethernet" {
		t.Errorf("eth0.Type = %q", eth0.Type)
	}
}

func TestParseDefaultRouteJSON(t *testing.T) {
	iface, gw, err := parseDefaultRouteJSON([]byte(ipRouteFixture))
	if err != nil {
		t.Fatal(err)
	}
	if iface != "eth0" || gw != "192.168.1.1" {
		t.Errorf("default route = iface=%q gw=%q", iface, gw)
	}
}

func TestParseDefaultRouteEmpty(t *testing.T) {
	// `ip -j route show default` returns `[]` when no default route — no error.
	iface, gw, err := parseDefaultRouteJSON([]byte("[]"))
	if err != nil {
		t.Fatalf("empty array must not error, got: %v", err)
	}
	if iface != "" || gw != "" {
		t.Errorf("expected empty strings, got iface=%q gw=%q", iface, gw)
	}
}

func TestParseResolvConf(t *testing.T) {
	r := strings.NewReader(resolvConfFixture)
	servers, domain, search := parseResolvConf(r)
	if len(servers) != 2 || servers[0] != "1.1.1.1" || servers[1] != "9.9.9.9" {
		t.Errorf("servers = %v", servers)
	}
	if domain != "example.com" {
		t.Errorf("domain = %q", domain)
	}
	if len(search) != 2 || search[0] != "example.com" {
		t.Errorf("search = %v", search)
	}
}
