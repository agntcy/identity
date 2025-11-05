// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package data

import (
	"github.com/agntcy/identity/internal/issuer/vault/types"
)

type VaultRepository interface {
	AddVault(vault *types.Vault) (string, error)
	GetAllVaults() ([]*types.Vault, error)
	GetVault(vaultId string) (*types.Vault, error)
	RemoveVault(vaultId string) error
}
