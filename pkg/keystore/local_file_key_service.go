// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"

	jwktype "github.com/agntcy/identity/pkg/jwk"
)

type LocalFileKeyService struct {
	FilePath string
	mu       sync.Mutex // to avoid concurrent writes
}

const filePerm = 0o644 // Read and write permissions for the owner only

// SaveKey saves or updates a JWK in the local file.
func (s *LocalFileKeyService) SaveKey(ctx context.Context, id string, jwk *jwktype.Jwk) error {
	if jwk == nil {
		return errors.New("jwk cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var jwks []jwktype.Jwk

	// Read existing keys if file exists
	file, err := os.OpenFile(s.FilePath, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&jwks); err != nil && err != io.EOF {
		return err
	}

	// Update or append the key
	found := false

	for i := range jwks {
		if jwks[i].KID == id {
			jwks[i] = *jwk
			found = true

			break
		}
	}

	if !found {
		jwks = append(jwks, *jwk)
	}

	// Write back all keys
	if err := file.Truncate(0); err != nil {
		return err
	}

	if _, err := file.Seek(0, 0); err != nil {
		return err
	}

	encoder := json.NewEncoder(file)

	return encoder.Encode(jwks)
}

// RetrievePubKey returns the public JWK for the given id.
func (s *LocalFileKeyService) RetrievePubKey(ctx context.Context, id string) (*jwktype.Jwk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jwks, err := s.readAll()
	if err != nil {
		return nil, err
	}

	for i := range jwks {
		if jwks[i].KID == id {
			pub := jwks[i].PublicKey()
			return pub, nil
		}
	}

	return nil, errors.New("public key not found")
}

// RetrievePrivKey returns the private JWK for the given id.
func (s *LocalFileKeyService) RetrievePrivKey(ctx context.Context, id string) (*jwktype.Jwk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jwks, err := s.readAll()
	if err != nil {
		return nil, err
	}

	for i := range jwks {
		if jwks[i].KID == id && jwks[i].D != "" {
			return &jwks[i], nil
		}

		if jwks[i].KID == id && jwks[i].PRIV != "" {
			return &jwks[i], nil
		}
	}

	return nil, errors.New("private key not found")
}

// readAll reads all JWKs from the file.
func (s *LocalFileKeyService) readAll() ([]jwktype.Jwk, error) {
	file, err := os.OpenFile(s.FilePath, os.O_RDONLY|os.O_CREATE, filePerm)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var jwks []jwktype.Jwk

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&jwks); err != nil && err != io.EOF {
		return nil, err
	}

	return jwks, nil
}

func (s *LocalFileKeyService) DeleteKey(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	jwks, err := s.readAll()
	if err != nil {
		return err
	}

	found := false
	filteredJwks := make([]jwktype.Jwk, 0, len(jwks))

	for i := range jwks {
		if jwks[i].KID != id {
			filteredJwks = append(filteredJwks, jwks[i])
		} else {
			found = true
		}
	}

	if !found {
		return errors.New("key not found")
	}

	file, err := os.OpenFile(s.FilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)

	return encoder.Encode(filteredJwks)
}

func (s *LocalFileKeyService) ListKeys(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	jwks, err := s.readAll()
	if err != nil {
		return nil, err
	}

	keyIDs := make([]string, 0, len(jwks))
	for i := range jwks {
		keyIDs = append(keyIDs, jwks[i].KID)
	}

	return keyIDs, nil
}
