// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	internalIssuerConstants "github.com/agntcy/identity/internal/issuer/constants"
	"github.com/agntcy/identity/internal/issuer/vault/data"
	"github.com/agntcy/identity/internal/issuer/vault/types"
)

type vaultFilesystemRepository struct{}

func NewVaultFilesystemRepository() data.VaultRepository {
	return &vaultFilesystemRepository{}
}

// getVaultsDirectory returns the path to the vaults directory
func getVaultsDirectory() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homeDir, ".identity", "vaults"), nil
}

// GetVaultIdDirectory returns the path to the vault ID directory
func GetVaultIdDirectory(vaultId string) (string, error) {
	vaultsDir, err := getVaultsDirectory()
	if err != nil {
		return "", err
	}

	return filepath.Join(vaultsDir, vaultId), nil
}

// GetVaultFilePath returns the path to the vault file
func GetVaultFilePath(vaultId string) (string, error) {
	vaultIdDir, err := GetVaultIdDirectory(vaultId)
	if err != nil {
		return "", err
	}

	return filepath.Join(vaultIdDir, "vault.json"), nil
}

func saveVaultConfig() error {
	return nil
}

func (r *vaultFilesystemRepository) AddVault(vault *types.Vault) (string, error) {
	// Save the vault config
	if err := saveVaultConfig(); err != nil {
		return "", err
	}

	// Create idp locally in the vault directory
	vaultsDir, err := GetVaultIdDirectory(vault.Id)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(vaultsDir, internalIssuerConstants.DirPerm); err != nil {
		return "", err
	}

	vaultFilePath, err := GetVaultFilePath(vault.Id)
	if err != nil {
		return "", err
	}

	// Marshal the config to JSON
	vaultData, err := json.Marshal(&vault)
	if err != nil {
		return "", err
	}

	// Write the vault to file
	if err := os.WriteFile(vaultFilePath, vaultData, internalIssuerConstants.FilePerm); err != nil {
		return "", err
	}

	return vault.Id, nil
}

func (r *vaultFilesystemRepository) GetAllVaults() ([]*types.Vault, error) {
	// Get the vaults directory
	vaultsDir, err := getVaultsDirectory()
	if err != nil {
		return nil, err
	}

	// Read the vaults directory
	files, err := os.ReadDir(vaultsDir)
	if err != nil {
		return nil, err
	}

	// List the vault IDs
	var vaultIds []*types.Vault

	for _, file := range files {
		if file.IsDir() {
			// Get the vault file path
			vault, err := r.GetVault(file.Name())
			if err != nil {
				return nil, err
			}

			// Append the vault to the list
			vaultIds = append(vaultIds, vault)
		}
	}

	return vaultIds, nil
}

func (r *vaultFilesystemRepository) GetVault(vaultId string) (*types.Vault, error) {
	// Get the vault file path
	vaultFilePath, err := GetVaultFilePath(vaultId)
	if err != nil {
		return nil, err
	}

	// Read the vault file
	vaultData, err := os.ReadFile(vaultFilePath)
	if err != nil {
		return nil, err
	}

	// Unmarshal the vault data depending on the vault type
	var vault types.Vault
	if err := vault.UnmarshalVault(vaultData); err != nil {
		return nil, err
	}

	return &vault, nil
}

func (r *vaultFilesystemRepository) RemoveVault(vaultId string) error {
	// Get the vault directory
	vaultDir, err := GetVaultIdDirectory(vaultId)
	if err != nil {
		return err
	}

	// Check if the vault directory exists
	if _, err := os.Stat(vaultDir); os.IsNotExist(err) {
		return errors.New("vault does not exist")
	}

	// Remove the vault directory
	if err := os.RemoveAll(vaultDir); err != nil {
		return err
	}

	return nil
}
