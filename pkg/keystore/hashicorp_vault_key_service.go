// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/agntcy/identity/pkg/jwk"
	"github.com/hashicorp/vault/api"
)

type VaultKeyService struct {
	client      *api.Client
	mountPath   string
	keyBasePath string
}

type VaultStorageConfig struct {
	Address     string
	Token       string
	MountPath   string
	KeyBasePath string
	Namespace   string
}

func (s *VaultKeyService) SaveKey(ctx context.Context, id string, priv *jwk.Jwk) error {
	if priv == nil {
		return errors.New("jwk cannot be nil")
	}

	jsonData, err := json.Marshal(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"jwk": string(jsonData),
		},
	}

	fullPath := s.buildKeyPath(id)

	_, err = s.client.Logical().WriteWithContext(ctx, fullPath, data)
	if err != nil {
		return fmt.Errorf("failed to write JWK to Vault: %w", err)
	}

	return nil
}

func (s *VaultKeyService) RetrievePubKey(ctx context.Context, id string) (*jwk.Jwk, error) {
	priv, err := s.retrieveKey(ctx, id)
	if err != nil {
		return nil, err
	}

	return priv.PublicKey(), nil
}

func (s *VaultKeyService) RetrievePrivKey(ctx context.Context, id string) (*jwk.Jwk, error) {
	return s.retrieveKey(ctx, id)
}

func (s *VaultKeyService) DeleteKey(ctx context.Context, id string) error {
	metadataPath := path.Join(s.mountPath, "metadata", s.keyBasePath, id)

	dataPath := s.buildKeyPath(id)

	secret, err := s.client.Logical().ReadWithContext(ctx, dataPath)
	if err != nil {
		return fmt.Errorf("failed to check if key exists: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return errors.New("key not found")
	}

	_, err = s.client.Logical().DeleteWithContext(ctx, metadataPath)
	if err != nil {
		return fmt.Errorf("failed to delete key from Vault: %w", err)
	}

	return nil
}

func (s *VaultKeyService) ListKeys(ctx context.Context) ([]string, error) {
	listPath := path.Join(s.mountPath, "metadata", s.keyBasePath)

	secret, err := s.client.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys in Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	keysRaw, ok := secret.Data["keys"]
	if !ok {
		return []string{}, nil
	}

	keysInterface, ok := keysRaw.([]interface{})
	if !ok {
		return nil, errors.New("unexpected format for keys list")
	}

	keys := make([]string, 0, len(keysInterface))

	for _, k := range keysInterface {
		if keyStr, ok := k.(string); ok {
			keys = append(keys, keyStr)
		}
	}

	return keys, nil
}

func (s *VaultKeyService) retrieveKey(ctx context.Context, id string) (*jwk.Jwk, error) {
	fullPath := s.buildKeyPath(id)

	secret, err := s.client.Logical().ReadWithContext(ctx, fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWK from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, errors.New("key not found in Vault")
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid data format in Vault")
	}

	jwkJSON, ok := data["jwk"].(string)
	if !ok {
		return nil, errors.New("JWK not found in Vault data")
	}

	var key jwk.Jwk
	if err := json.Unmarshal([]byte(jwkJSON), &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK: %w", err)
	}

	return &key, nil
}

func (s *VaultKeyService) buildKeyPath(id string) string {
	return path.Join(s.mountPath, "data", s.keyBasePath, id)
}
