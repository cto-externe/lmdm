// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"bufio"
	"io"
	"runtime"
	"strconv"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// parseCPUInfo reads /proc/cpuinfo-style content and summarizes it into a
// single CPUInfo. All processor records are assumed to describe the same
// CPU (single-socket host).
//
// Architecture-specific notes:
//   - amd64: "model name", "cpu cores", "siblings", "cpu MHz", "flags" are
//     all present and populated. This is the MVP target.
//   - arm64: "model name" is often absent on generic ARM Linux; "cpu cores"
//     and "siblings" are usually present. We degrade gracefully — an empty
//     Model is acceptable. Populating Model on ARM requires reading
//     /sys/firmware/devicetree/base/model or /proc/device-tree/model, which
//     is deferred to a future enrichment pass.
//   - Any other arch: same degrade-to-empty behavior. The parser never
//     panics or errors on unknown/missing keys.
func parseCPUInfo(r io.Reader) *lmdmv1.CPUInfo {
	cpu := &lmdmv1.CPUInfo{Arch: runtime.GOARCH}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var siblings, cores int
	var processors int
	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := splitCPUField(line)
		if !ok {
			continue
		}
		switch key {
		case "processor":
			processors++
		case "model name":
			if cpu.Model == "" {
				cpu.Model = val
			}
		case "cpu cores":
			if n, err := strconv.Atoi(val); err == nil && cores == 0 {
				cores = n
			}
		case "siblings":
			if n, err := strconv.Atoi(val); err == nil && siblings == 0 {
				siblings = n
			}
		case "cpu MHz":
			if f, err := strconv.ParseFloat(val, 64); err == nil && cpu.FrequencyMhz == 0 {
				cpu.FrequencyMhz = uint32(f)
			}
		case "flags", "Features": // x86 uses "flags", ARM uses "Features"
			if len(cpu.Flags) == 0 {
				cpu.Flags = strings.Fields(val)
			}
		}
	}

	cpu.Cores = uint32(cores)
	// siblings is the total logical CPUs per physical socket → thread count.
	// Fall back to the number of "processor" records if unavailable.
	if siblings > 0 {
		cpu.Threads = uint32(siblings)
	} else {
		cpu.Threads = uint32(processors)
	}
	return cpu
}

// splitCPUField splits a line like "model name\t: AMD Ryzen ..." into the
// key and value parts. Returns ok=false for non-"key: value" lines.
func splitCPUField(line string) (key, val string, ok bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	val = strings.TrimSpace(line[idx+1:])
	return key, val, true
}
