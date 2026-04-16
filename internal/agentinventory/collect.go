// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"bytes"
	"os"
	"os/exec"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// Snapshot is the collected inventory, ready to be wrapped into an
// InventoryReport. Fields correspond 1:1 to the proto sub-messages.
type Snapshot struct {
	Hardware *lmdmv1.HardwareInventory
	Software *lmdmv1.SoftwareInventory
	Network  *lmdmv1.NetworkInventory
}

// Collect runs every sub-collector and aggregates the results. Per-collector
// errors degrade the result (missing fields) rather than failing the whole
// collection — an inventory report with a missing battery or unknown TPM is
// still useful.
func Collect() *Snapshot {
	return &Snapshot{
		Hardware: collectHardware(),
		Software: collectSoftware(),
		Network:  collectNetwork(),
	}
}

// ToReport wraps a Snapshot in a full InventoryReport with device_id and
// timestamp. MVP always emits full reports (is_full = true).
func ToReport(s *Snapshot, deviceID string) *lmdmv1.InventoryReport {
	return &lmdmv1.InventoryReport{
		DeviceId:      &lmdmv1.DeviceID{Id: deviceID},
		Timestamp:     timestamppb.New(time.Now().UTC()),
		IsFull:        true,
		SchemaVersion: 1,
		Hardware:      s.Hardware,
		Software:      s.Software,
		Network:       s.Network,
	}
}

func collectHardware() *lmdmv1.HardwareInventory {
	dmi := readDMIMap(dmiRoot)

	var cpu *lmdmv1.CPUInfo
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		cpu = parseCPUInfo(f)
		_ = f.Close()
	} else {
		cpu = &lmdmv1.CPUInfo{}
	}

	var mem *lmdmv1.MemoryInfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		mem = parseMemInfo(f)
		_ = f.Close()
	} else {
		mem = &lmdmv1.MemoryInfo{Modules: []*lmdmv1.MemoryModule{}}
	}

	var disks []*lmdmv1.DiskInfo
	if out, err := exec.Command("lsblk", "-J", "-b", "-o",
		"NAME,MODEL,SERIAL,SIZE,TYPE,TRAN,ROTA").Output(); err == nil {
		if parsed, err := parseLsblkJSON(out); err == nil {
			disks = parsed
		}
	}
	if disks == nil {
		disks = []*lmdmv1.DiskInfo{}
	}

	return &lmdmv1.HardwareInventory{
		System:            dmiToSystemInfo(dmi),
		Cpu:               cpu,
		Memory:            mem,
		Disks:             disks,
		Gpus:              []*lmdmv1.GPUInfo{}, // out of scope at MVP
		Bios:              dmiToBIOSInfo(dmi),
		Tpm:               collectTPMFrom(tpmRoot),         // nil if no TPM
		Battery:           collectBatteryFrom(batteryRoot), // nil if no battery
		UsbDevices:        []*lmdmv1.USBDevice{},           // out of scope at MVP
		SecureBootEnabled: false,                           // out of scope at MVP
	}
}

func collectSoftware() *lmdmv1.SoftwareInventory {
	var osInfo *lmdmv1.OSInfo
	if f, err := os.Open("/etc/os-release"); err == nil {
		osInfo = parseOSRelease(f)
		_ = f.Close()
	} else {
		osInfo = &lmdmv1.OSInfo{}
	}
	// Kernel is available via uname; shell out since the stdlib doesn't
	// expose uname easily.
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		osInfo.Kernel = string(bytes.TrimSpace(out))
	}

	var packages []*lmdmv1.Package
	if osInfo.Family == lmdmv1.OSFamily_OS_FAMILY_DEBIAN {
		if out, err := exec.Command("dpkg-query", "-W",
			"-f=${Package}\t${Version}\t${Architecture}\t${Installed-Size}\n").Output(); err == nil {
			packages = parseDpkgQuery(bytes.NewReader(out))
		}
	}
	if packages == nil {
		packages = []*lmdmv1.Package{}
	}

	var services []*lmdmv1.SystemdService
	if out, err := exec.Command("systemctl", "list-units", "--type=service",
		"--all", "--no-pager", "--plain", "--no-legend").Output(); err == nil {
		services = parseSystemctlList(bytes.NewReader(out))
	}
	if services == nil {
		services = []*lmdmv1.SystemdService{}
	}

	return &lmdmv1.SoftwareInventory{
		Os:              osInfo,
		Packages:        packages,
		PackagesAdded:   []*lmdmv1.Package{},
		PackagesRemoved: []*lmdmv1.Package{},
		Services:        services,
		Flatpaks:        []*lmdmv1.Package{}, // out of scope
		Snaps:           []*lmdmv1.Package{}, // out of scope
	}
}

func collectNetwork() *lmdmv1.NetworkInventory {
	hostname, _ := os.Hostname()

	var ifaces []*lmdmv1.NetworkInterface
	if out, err := exec.Command("ip", "-j", "addr").Output(); err == nil {
		if parsed, err := parseIPAddrJSON(out); err == nil {
			ifaces = parsed
		}
	}
	if ifaces == nil {
		ifaces = []*lmdmv1.NetworkInterface{}
	}

	var dns []string
	var domain string
	var search []string
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		dns, domain, search = parseResolvConf(f)
		_ = f.Close()
	}

	var defIface, defGw string
	if out, err := exec.Command("ip", "-j", "route", "show", "default").Output(); err == nil {
		defIface, defGw, _ = parseDefaultRouteJSON(out)
	}

	return &lmdmv1.NetworkInventory{
		Hostname:         hostname,
		Interfaces:       ifaces,
		DnsServers:       dns,
		DnsDomain:        domain,
		DnsSearch:        search,
		DefaultGateway:   defGw,
		DefaultInterface: defIface,
		HttpProxy:        os.Getenv("http_proxy"),
		HttpsProxy:       os.Getenv("https_proxy"),
		NoProxy:          os.Getenv("no_proxy"),
		ListeningPorts:   []*lmdmv1.ListeningPort{}, // out of scope at MVP
	}
}
