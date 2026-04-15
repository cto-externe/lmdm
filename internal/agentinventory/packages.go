// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// parseDpkgQuery parses the tab-separated output of
// `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Installed-Size}\n'`.
// Malformed lines (not exactly 4 tab-separated fields) are silently skipped.
func parseDpkgQuery(r io.Reader) []*lmdmv1.Package {
	out := []*lmdmv1.Package{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			continue
		}
		size, _ := strconv.ParseUint(parts[3], 10, 64)
		out = append(out, &lmdmv1.Package{
			Name:            parts[0],
			Version:         parts[1],
			Arch:            parts[2],
			Source:          "apt",
			InstalledSizeKb: size,
		})
	}
	return out
}
