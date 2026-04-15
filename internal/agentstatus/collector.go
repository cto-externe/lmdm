// Package agentstatus collects local system metrics from /proc and syscalls
// to build a Heartbeat proto. Linux-only at MVP.
package agentstatus

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Snapshot is the raw collected metrics.
type Snapshot struct {
	UptimeSeconds uint64
	LoadAvg1m     float64
	LoadAvg5m     float64
	LoadAvg15m    float64
	RAMUsedMB     uint64
	RAMTotalMB    uint64
	DiskUsedGB    uint64
	DiskTotalGB   uint64
	DiskUsedPct   uint32
}

// Collect reads /proc/uptime, /proc/loadavg, /proc/meminfo and statfs("/")
// to populate a Snapshot.
func Collect() (*Snapshot, error) {
	s := &Snapshot{}
	if err := readUptime(s); err != nil {
		return nil, err
	}
	if err := readLoadAvg(s); err != nil {
		return nil, err
	}
	if err := readMemInfo(s); err != nil {
		return nil, err
	}
	if err := readDiskUsage(s, "/"); err != nil {
		return nil, err
	}
	return s, nil
}

func readUptime(s *Snapshot) error {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return fmt.Errorf("agentstatus: read /proc/uptime: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return fmt.Errorf("agentstatus: empty /proc/uptime")
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return fmt.Errorf("agentstatus: parse uptime: %w", err)
	}
	s.UptimeSeconds = uint64(v)
	return nil
}

func readLoadAvg(s *Snapshot) error {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return fmt.Errorf("agentstatus: read /proc/loadavg: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return fmt.Errorf("agentstatus: malformed /proc/loadavg")
	}
	parse := func(i int) (float64, error) { return strconv.ParseFloat(fields[i], 64) }
	var err1, err2, err3 error
	s.LoadAvg1m, err1 = parse(0)
	s.LoadAvg5m, err2 = parse(1)
	s.LoadAvg15m, err3 = parse(2)
	for _, e := range []error{err1, err2, err3} {
		if e != nil {
			return fmt.Errorf("agentstatus: parse loadavg: %w", e)
		}
	}
	return nil
}

func readMemInfo(s *Snapshot) error {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("agentstatus: open /proc/meminfo: %w", err)
	}
	defer f.Close()

	var totalKB, availKB uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB = parseKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			availKB = parseKB(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("agentstatus: scan meminfo: %w", err)
	}
	s.RAMTotalMB = totalKB / 1024
	if availKB > totalKB {
		availKB = totalKB
	}
	s.RAMUsedMB = (totalKB - availKB) / 1024
	return nil
}

func parseKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func readDiskUsage(s *Snapshot, path string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fmt.Errorf("agentstatus: statfs %s: %w", path, err)
	}
	totalBytes := st.Blocks * uint64(st.Bsize)
	freeBytes := st.Bavail * uint64(st.Bsize)
	usedBytes := totalBytes - freeBytes
	s.DiskTotalGB = totalBytes / (1 << 30)
	s.DiskUsedGB = usedBytes / (1 << 30)
	if totalBytes > 0 {
		s.DiskUsedPct = uint32((usedBytes * 100) / totalBytes)
	}
	return nil
}
