// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"fmt"

	vaulttypes "github.com/agntcy/identity/internal/issuer/vault/types"
	"github.com/agntcy/identity/pkg/keystore"
)

func newKeyService(vault *vaulttypes.Vault) (keystore.KeyService, error) {
	switch vault.Type {
	case vaulttypes.VaultTypeFile:
		fileVault, ok := vault.Config.(*vaulttypes.VaultFile)
		if !ok {
			return nil, fmt.Errorf("error: vault config is not of type VaultFile")
		}

		fileConfig := keystore.FileStorageConfig{
			FilePath: fileVault.FilePath,
		}

		service, err := keystore.NewKeyService(keystore.FileStorage, fileConfig)
		if err != nil {
			return nil, fmt.Errorf("error creating key service: %w", err)
		}

		return service, nil
	case vaulttypes.VaultTypeHashicorp:
		hashicorpVault, ok := vault.Config.(*vaulttypes.VaultHashicorp)
		if !ok {
			return nil, fmt.Errorf("error: vault config is not of type VaultHashicorp")
		}

		hashicorpConfig := keystore.VaultStorageConfig{
			Address:   hashicorpVault.Address,
			Token:     hashicorpVault.Token,
			Namespace: hashicorpVault.Namespace,
		}

		service, err := keystore.NewKeyService(keystore.VaultStorage, hashicorpConfig)
		if err != nil {
			return nil, fmt.Errorf("error creating key service: %w", err)
		}

		return service, nil
	default:
		return nil, fmt.Errorf("unsupported vault type: %s", vault.Type)
	}
}
