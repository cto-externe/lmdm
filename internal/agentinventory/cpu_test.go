// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"strings"
	"testing"
)

const cpuinfoFixture = `processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 116
model name	: AMD Ryzen 7 PRO 7840U w/ Radeon 780M Graphics
stepping	: 1
cpu MHz		: 3300.000
cache size	: 1024 KB
physical id	: 0
siblings	: 16
core id		: 0
cpu cores	: 8
fpu		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch

processor	: 1
vendor_id	: AuthenticAMD
cpu family	: 25
`

func TestParseCPUInfo(t *testing.T) {
	cpu := parseCPUInfo(strings.NewReader(cpuinfoFixture))
	if cpu.Model != "AMD Ryzen 7 PRO 7840U w/ Radeon 780M Graphics" {
		t.Errorf("Model = %q", cpu.Model)
	}
	if cpu.Cores != 8 {
		t.Errorf("Cores = %d, want 8", cpu.Cores)
	}
	if cpu.Threads != 16 {
		t.Errorf("Threads = %d, want 16", cpu.Threads)
	}
	if cpu.FrequencyMhz != 3300 {
		t.Errorf("FrequencyMhz = %d", cpu.FrequencyMhz)
	}
	if len(cpu.Flags) == 0 {
		t.Fatal("Flags must not be empty")
	}
	// Spot-check: we expect at least one flag we know is present.
	found := false
	for _, f := range cpu.Flags {
		if f == "avx" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'avx' in Flags")
	}
}

func TestParseCPUInfoEmpty(t *testing.T) {
	cpu := parseCPUInfo(strings.NewReader(""))
	if cpu == nil {
		t.Fatal("parseCPUInfo must never return nil")
	}
	if cpu.Cores != 0 {
		t.Errorf("Cores on empty input = %d", cpu.Cores)
	}
}

// ARM cpuinfo uses "Features" (not "flags") and often lacks "model name".
// The parser must degrade gracefully: empty Model, populated Flags, Threads
// derived from the processor record count when siblings is absent.
const cpuinfoARMFixture = `processor	: 0
BogoMIPS	: 243.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x1
CPU part	: 0xd0b
CPU revision	: 0

processor	: 1
BogoMIPS	: 243.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid
`

func TestParseCPUInfoARM(t *testing.T) {
	cpu := parseCPUInfo(strings.NewReader(cpuinfoARMFixture))
	// Model is intentionally empty on generic ARM — degrade gracefully, do
	// not crash.
	if cpu.Model != "" {
		t.Errorf("Model on ARM fixture = %q, want empty (degrade gracefully)", cpu.Model)
	}
	// Two "processor" records → Threads = 2 when siblings is absent.
	if cpu.Threads != 2 {
		t.Errorf("Threads = %d, want 2 (fallback to processor count)", cpu.Threads)
	}
	// Features parsed as flags.
	if len(cpu.Flags) == 0 {
		t.Error("Flags should be populated from 'Features' line on ARM")
	}
}
