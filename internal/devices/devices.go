// Package devices persists managed devices (workstations, printers, etc.).
// At the MVP only workstation rows are inserted at enrollment time.
package devices

import (
	"time"

	"github.com/google/uuid"
)

// Type enumerates the supported device families. Mirrors the SQL enum.
type Type string

// Supported device type values. Mirror the SQL enum.
const (
	TypeWorkstation Type = "workstation"
	TypePrinter     Type = "printer"
	TypeNetwork     Type = "network"
	TypeMobile      Type = "mobile"
)

// Status mirrors the SQL enum.
type Status string

// Supported device status values. Mirror the SQL enum.
const (
	StatusOnline         Status = "online"
	StatusOffline        Status = "offline"
	StatusDegraded       Status = "degraded"
	StatusDecommissioned Status = "decommissioned"
)

// Device is the persisted record. Nullable fields use pointers.
type Device struct {
	ID                 uuid.UUID
	TenantID           uuid.UUID
	Type               Type
	Hostname           string
	SerialNumber       *string
	Manufacturer       *string
	Model              *string
	SiteID             *uuid.UUID
	Status             Status
	LastSeen           *time.Time
	EnrolledAt         time.Time
	EnrolledViaToken   *uuid.UUID
	AgentPubkeyEd25519 []byte
	AgentPubkeyMLDSA   []byte
	CertSerial         *string
	AgentVersion       *string
}
