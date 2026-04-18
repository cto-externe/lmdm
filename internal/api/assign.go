// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"net/http"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/profiles"
)

func (d *Deps) handleAssignProfile(w http.ResponseWriter, r *http.Request) {
	profileID, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid profile id")
		return
	}
	deviceID, ok := parseUUID(r, "deviceID")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	ctx := r.Context()

	// Assign in DB.
	if err := d.Profiles.Assign(ctx, d.TenantID, profileID, "device", deviceID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Load profile to get YAML + signatures.
	p, err := d.Profiles.FindByID(ctx, d.TenantID, profileID)
	if err != nil {
		if err == profiles.ErrNotFound {
			writeError(w, http.StatusNotFound, "profile not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Push via NATS as ApplyProfileCommand.
	env := &lmdmv1.CommandEnvelope{
		CommandId: profileID.String() + "-" + deviceID.String(),
		Command: &lmdmv1.CommandEnvelope_ApplyProfile{
			ApplyProfile: &lmdmv1.ApplyProfileCommand{
				ProfileId:      &lmdmv1.ProfileID{Id: profileID.String()},
				Version:        p.Version,
				ProfileContent: []byte(p.YAMLContent),
				ProfileSignature: &lmdmv1.HybridSignature{
					Ed25519: p.SignatureEd25519,
					MlDsa:   p.SignatureMLDSA,
				},
			},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal command: "+err.Error())
		return
	}
	subject := "fleet.agent." + deviceID.String() + ".commands"
	if d.NATS != nil {
		if err := d.NATS.Publish(subject, data); err != nil {
			writeError(w, http.StatusInternalServerError, "nats publish: "+err.Error())
			return
		}
		_ = d.NATS.Flush()
	}

	if pr := auth.PrincipalFrom(ctx); pr != nil && d.Audit != nil {
		_ = d.Audit.Write(ctx, audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(pr.UserID),
			Action:       audit.ActionProfileAssigned,
			ResourceType: "profile",
			ResourceID:   profileID.String(),
			SourceIP:     clientIP(r),
			Details:      map[string]any{"device_id": deviceID.String()},
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "profile assigned and pushed",
		"profile": profileID,
		"device":  deviceID,
	})
}
