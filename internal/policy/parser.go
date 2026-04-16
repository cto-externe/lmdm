// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ProfileDef is the parsed top-level structure of a profile YAML file.
type ProfileDef struct {
	Kind        string          `yaml:"kind"`
	Name        string          `yaml:"-"`
	Version     string          `yaml:"-"`
	Description string          `yaml:"-"`
	Locked      bool            `yaml:"-"`
	Metadata    profileMetadata `yaml:"metadata"`
	Policies    []NamedPolicy   `yaml:"policies"`
}

type profileMetadata struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	Locked      bool   `yaml:"locked"`
}

// NamedPolicy is one named policy within a profile.
type NamedPolicy struct {
	Name    string      `yaml:"name"`
	Actions []ActionDef `yaml:"actions"`
}

// ActionDef is a single action within a policy.
type ActionDef struct {
	Type   string         `yaml:"type"`
	Params map[string]any `yaml:"params"`
}

// ParseProfile parses the YAML and instantiates all actions via the registry.
// Returns the profile definition (metadata) and the flat list of typed
// actions ready for the executor. Returns an error if YAML is malformed or
// any action type is unknown.
func ParseProfile(yamlBytes []byte, reg *Registry) (*ProfileDef, []TypedAction, error) {
	var def ProfileDef
	if err := yaml.Unmarshal(yamlBytes, &def); err != nil {
		return nil, nil, fmt.Errorf("parse profile: %w", err)
	}
	def.Name = def.Metadata.Name
	def.Version = def.Metadata.Version
	def.Description = def.Metadata.Description
	def.Locked = def.Metadata.Locked

	var actions []TypedAction
	for _, pol := range def.Policies {
		for _, ad := range pol.Actions {
			ctor, ok := reg.Lookup(ad.Type)
			if !ok {
				return nil, nil, fmt.Errorf("parse profile: unknown action type %q in policy %q", ad.Type, pol.Name)
			}
			a, err := ctor(ad.Params)
			if err != nil {
				return nil, nil, fmt.Errorf("parse profile: action %q in policy %q: %w", ad.Type, pol.Name, err)
			}
			if err := a.Validate(); err != nil {
				return nil, nil, fmt.Errorf("parse profile: validate %q in policy %q: %w", ad.Type, pol.Name, err)
			}
			actions = append(actions, TypedAction{Type: ad.Type, Action: a})
		}
	}
	return &def, actions, nil
}
