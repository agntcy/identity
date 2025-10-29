// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"fmt"
)

// VaultType represents the type of vault
type VaultType string

const (
	VaultTypeFile      VaultType = "file"
	VaultTypeHashicorp VaultType = "hashicorp"
)

// VaultConfig is an interface that all vault implementations must satisfy
type VaultConfig interface {
	GetVaultType() VaultType
}

type Vault struct {
	// The ID of the vault
	Id string `json:"id,omitempty"`
	// The name of the vault
	Name string `json:"name,omitempty"`
	// The type of the vault
	Type VaultType `json:"type,omitempty"`
	// The vault implementation
	Config VaultConfig `json:"config,omitempty"`
}

type VaultFile struct {
	// The text file vault path
	FilePath string `json:"path,omitempty"`
}

// GetVaultType returns the type of this vault implementation
func (v *VaultFile) GetVaultType() VaultType {
	return VaultTypeFile
}

type VaultHashicorp struct {
	// The address of the HashiCorp Vault server
	Address string `json:"address,omitempty"`
	// The token to authenticate with the HashiCorp Vault server
	Token string `json:"token,omitempty"`
	// The namespace to use in the HashiCorp Vault server
	Namespace string `json:"namespace,omitempty"`
}

// GetVaultType returns the type of this vault implementation
func (v *VaultHashicorp) GetVaultType() VaultType {
	return VaultTypeHashicorp
}

// UnmarshalVault implements custom JSON unmarshaling for Vault
func (v *Vault) UnmarshalVault(data []byte) error {
	// Temporary struct to decode the JSON data
	type tempVault struct {
		Id     string          `json:"id,omitempty"`
		Name   string          `json:"name,omitempty"`
		Type   VaultType       `json:"type,omitempty"`
		Config json.RawMessage `json:"config,omitempty"`
	}

	var temp tempVault
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Assign basic fields
	v.Id = temp.Id
	v.Name = temp.Name
	v.Type = temp.Type

	// Skip if no config is provided
	if len(temp.Config) == 0 {
		v.Config = nil
		return nil
	}

	// Create the appropriate VaultConfig based on the Type
	switch temp.Type {
	case VaultTypeFile:
		var config VaultFile
		if err := json.Unmarshal(temp.Config, &config); err != nil {
			return err
		}

		v.Config = &config

	case VaultTypeHashicorp:
		var config VaultHashicorp
		if err := json.Unmarshal(temp.Config, &config); err != nil {
			return err
		}

		v.Config = &config

	default:
		return fmt.Errorf("unknown vault type: %s", temp.Type)
	}

	return nil
}
