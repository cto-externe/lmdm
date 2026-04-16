// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package profiles persists profile definitions (YAML + JSONB + PQ signatures)
// and their assignments to devices/groups.
package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

// Profile is the persisted record.
type Profile struct {
	ID               uuid.UUID
	TenantID         uuid.UUID
	Name             string
	Version          string
	Description      string
	YAMLContent      string
	JSONContent      json.RawMessage
	SignatureEd25519 []byte
	SignatureMLDSA   []byte
	Source           string
	Locked           bool
	CreatedAt        time.Time
}

// ErrNotFound is returned when no profile matches.
var ErrNotFound = errors.New("profiles: not found")

// Repository wraps the DB + server signing key.
type Repository struct {
	pool       *db.Pool
	serverPriv *pqhybrid.SigningPrivateKey
}

// NewRepository wires a Repository.
func NewRepository(pool *db.Pool, serverPriv *pqhybrid.SigningPrivateKey) *Repository {
	return &Repository{pool: pool, serverPriv: serverPriv}
}

// Create parses the YAML, signs it with the server's PQ key, and persists it.
func (r *Repository) Create(ctx context.Context, tenantID uuid.UUID, yamlBytes []byte) (*Profile, error) {
	var raw struct {
		Metadata struct {
			Name        string `yaml:"name"`
			Version     string `yaml:"version"`
			Description string `yaml:"description"`
			Locked      bool   `yaml:"locked"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return nil, fmt.Errorf("profiles: parse yaml: %w", err)
	}

	var jsonMap any
	if err := yaml.Unmarshal(yamlBytes, &jsonMap); err != nil {
		return nil, fmt.Errorf("profiles: yaml→json: %w", err)
	}
	jsonBytes, err := json.Marshal(convertYAMLToJSON(jsonMap))
	if err != nil {
		return nil, fmt.Errorf("profiles: marshal json: %w", err)
	}

	sig, err := pqhybrid.Sign(r.serverPriv, yamlBytes)
	if err != nil {
		return nil, fmt.Errorf("profiles: sign: %w", err)
	}

	p := &Profile{
		TenantID:         tenantID,
		Name:             raw.Metadata.Name,
		Version:          raw.Metadata.Version,
		Description:      raw.Metadata.Description,
		YAMLContent:      string(yamlBytes),
		JSONContent:      jsonBytes,
		SignatureEd25519: sig.Ed25519,
		SignatureMLDSA:   sig.MLDSA,
		Locked:           raw.Metadata.Locked,
	}

	const q = `
		INSERT INTO profiles
		    (tenant_id, name, version, description, yaml_content, json_content,
		     signature_ed25519, signature_mldsa, locked)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, source, created_at
	`
	err = r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q,
			tenantID, p.Name, p.Version, p.Description, p.YAMLContent, p.JSONContent,
			p.SignatureEd25519, p.SignatureMLDSA, p.Locked,
		).Scan(&p.ID, &p.Source, &p.CreatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("profiles: insert: %w", err)
	}
	return p, nil
}

// FindByID returns a profile by id.
func (r *Repository) FindByID(ctx context.Context, tenantID, id uuid.UUID) (*Profile, error) {
	const q = `
		SELECT id, tenant_id, name, version, description, yaml_content, json_content,
		       signature_ed25519, signature_mldsa, source, locked, created_at
		  FROM profiles WHERE id = $1
	`
	var p Profile
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, id).Scan(
			&p.ID, &p.TenantID, &p.Name, &p.Version, &p.Description,
			&p.YAMLContent, &p.JSONContent,
			&p.SignatureEd25519, &p.SignatureMLDSA,
			&p.Source, &p.Locked, &p.CreatedAt,
		)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("profiles: find: %w", err)
	}
	return &p, nil
}

// Assign creates a profile assignment to a target (device/group/tenant).
func (r *Repository) Assign(ctx context.Context, tenantID, profileID uuid.UUID, targetType string, targetID uuid.UUID) error {
	const q = `
		INSERT INTO profile_assignments (tenant_id, profile_id, target_type, target_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (profile_id, target_type, target_id) DO NOTHING
	`
	return r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, tenantID, profileID, targetType, targetID)
		return err
	})
}

// ListAssigned returns the profiles assigned to a target.
func (r *Repository) ListAssigned(ctx context.Context, tenantID uuid.UUID, targetType string, targetID uuid.UUID) ([]Profile, error) {
	const q = `
		SELECT p.id, p.tenant_id, p.name, p.version, p.description, p.yaml_content,
		       p.json_content, p.signature_ed25519, p.signature_mldsa, p.source, p.locked, p.created_at
		  FROM profiles p
		  JOIN profile_assignments pa ON pa.profile_id = p.id
		 WHERE pa.target_type = $1 AND pa.target_id = $2
		 ORDER BY pa.priority
	`
	var out []Profile
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, targetType, targetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Profile
			if err := rows.Scan(
				&p.ID, &p.TenantID, &p.Name, &p.Version, &p.Description,
				&p.YAMLContent, &p.JSONContent,
				&p.SignatureEd25519, &p.SignatureMLDSA,
				&p.Source, &p.Locked, &p.CreatedAt,
			); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("profiles: list assigned: %w", err)
	}
	return out, nil
}

// List returns all profiles for a tenant (most recent first, limit 100).
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID) ([]Profile, error) {
	const q = `
		SELECT id, tenant_id, name, version, description, yaml_content, json_content,
		       signature_ed25519, signature_mldsa, source, locked, created_at
		  FROM profiles
		 ORDER BY created_at DESC
		 LIMIT 100
	`
	var out []Profile
	err := r.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Profile
			if err := rows.Scan(
				&p.ID, &p.TenantID, &p.Name, &p.Version, &p.Description,
				&p.YAMLContent, &p.JSONContent,
				&p.SignatureEd25519, &p.SignatureMLDSA,
				&p.Source, &p.Locked, &p.CreatedAt,
			); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("profiles: list: %w", err)
	}
	return out, nil
}

// Pool returns the underlying pool for callers that bypass RLS.
func (r *Repository) Pool() *db.Pool { return r.pool }

func (r *Repository) withTenant(ctx context.Context, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('lmdm.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// convertYAMLToJSON recursively converts YAML-parsed maps (which use
// map[any]any for nested structures) to JSON-compatible map[string]any.
func convertYAMLToJSON(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, v2 := range val {
			out[k] = convertYAMLToJSON(v2)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(val))
		for k, v2 := range val {
			out[fmt.Sprintf("%v", k)] = convertYAMLToJSON(v2)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, v2 := range val {
			out[i] = convertYAMLToJSON(v2)
		}
		return out
	default:
		return v
	}
}
