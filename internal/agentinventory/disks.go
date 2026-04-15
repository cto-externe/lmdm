// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentinventory

import (
	"encoding/json"
	"fmt"
	"strconv"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// lsblkEntry mirrors the JSON schema produced by
// `lsblk -J -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN,ROTA`.
// Fields we don't use are omitted.
type lsblkEntry struct {
	Name   string  `json:"name"`
	Model  *string `json:"model"`
	Serial *string `json:"serial"`
	Size   string  `json:"size"` // bytes as string
	Type   string  `json:"type"` // "disk" / "part" / "rom" / "loop"
	Tran   *string `json:"tran"`
	Rota   string  `json:"rota"` // "0" / "1"
}

type lsblkRoot struct {
	BlockDevices []lsblkEntry `json:"blockdevices"`
}

// parseLsblkJSON turns `lsblk -J` output into []DiskInfo, keeping only
// type=disk entries.
func parseLsblkJSON(data []byte) ([]*lmdmv1.DiskInfo, error) {
	var root lsblkRoot
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("lsblk: %w", err)
	}
	out := make([]*lmdmv1.DiskInfo, 0, len(root.BlockDevices))
	for _, e := range root.BlockDevices {
		if e.Type != "disk" {
			continue
		}
		size, _ := strconv.ParseUint(e.Size, 10, 64)
		tran := derefOr(e.Tran, "")
		out = append(out, &lmdmv1.DiskInfo{
			Name:           e.Name,
			Model:          derefOr(e.Model, ""),
			Serial:         derefOr(e.Serial, ""),
			SizeGb:         size / (1 << 30),
			Type:           diskType(tran, e.Rota),
			Transport:      tran,
			SmartSupported: tran == "sata" || tran == "nvme",
		})
	}
	return out, nil
}

// diskType classifies the disk based on transport and rotational flag.
func diskType(tran, rota string) string {
	switch tran {
	case "nvme":
		return "ssd_nvme"
	case "sata":
		if rota == "0" {
			return "ssd_sata"
		}
		return "hdd"
	case "usb":
		return "usb"
	default:
		return "unknown"
	}
}

func derefOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}
