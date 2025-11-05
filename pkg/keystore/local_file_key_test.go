// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package keystore_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/agntcy/identity/pkg/joseutil"
	"github.com/agntcy/identity/pkg/keystore"
	"github.com/stretchr/testify/assert"
)

func tempFilePath() string {
	f, err := os.CreateTemp("", "jwkstore-*.json")
	if err != nil {
		panic(err)
	}

	path := f.Name()
	f.Close()
	os.Remove(path)

	return path
}

func TestLocalFileKeyService_SaveAndRetrieve_RSA(t *testing.T) {
	t.Parallel()

	filePath := tempFilePath()
	defer os.Remove(filePath)

	config := keystore.FileStorageConfig{
		FilePath: filePath,
	}

	service, err := keystore.NewKeyService(keystore.FileStorage, config)
	assert.NoError(t, err, "Failed to create key service")

	priv, err := joseutil.GenerateJWK("RS256", "sig", "test-rsa")
	assert.NoError(t, err, "GenerateJWK failed")

	ctx := context.Background()
	err = service.SaveKey(ctx, priv.KID, priv)
	assert.NoError(t, err, "SaveKey failed")

	// Retrieve public key
	pub, err := service.RetrievePubKey(ctx, priv.KID)
	assert.NoError(t, err, "RetrievePubKey failed")

	// Verify public key doesn't contain private fields
	assert.Empty(t, pub.D, "PublicJWK should not contain private D field")
	assert.Empty(t, pub.P, "PublicJWK should not contain private P field")
	assert.Empty(t, pub.Q, "PublicJWK should not contain private Q field")
	assert.Empty(t, pub.DP, "PublicJWK should not contain private DP field")
	assert.Empty(t, pub.DQ, "PublicJWK should not contain private DQ field")
	assert.Empty(t, pub.QI, "PublicJWK should not contain private QI field")

	// Verify public key contains correct public fields
	assert.Equal(t, priv.N, pub.N, "PublicJWK should contain correct N field")
	assert.Equal(t, priv.E, pub.E, "PublicJWK should contain correct E field")

	// Retrieve private key
	gotPriv, err := service.RetrievePrivKey(ctx, priv.KID)
	assert.NoError(t, err, "RetrievePrivKey failed")

	// Verify private key contains correct fields
	assert.Equal(t, priv.D, gotPriv.D, "Private key should contain correct D field")
	assert.Equal(t, priv.P, gotPriv.P, "Private key should contain correct P field")
	assert.Equal(t, priv.Q, gotPriv.Q, "Private key should contain correct Q field")
}

func TestLocalFileKeyService_NotFound(t *testing.T) {
	t.Parallel()

	filePath := tempFilePath()
	defer os.Remove(filePath)

	config := keystore.FileStorageConfig{
		FilePath: filePath,
	}

	service, err := keystore.NewKeyService(keystore.FileStorage, config)
	assert.NoError(t, err, "Failed to create key service")

	ctx := context.Background()

	_, err = service.RetrievePubKey(ctx, "not-exist")
	assert.Error(t, err, "Should error for non-existent public key")

	_, err = service.RetrievePrivKey(ctx, "not-exist")
	assert.Error(t, err, "Should error for non-existent private key")
}

func TestNewKeyService_InvalidConfig(t *testing.T) {
	t.Parallel()

	wrongConfig := struct{ Wrong string }{"wrong"}
	_, err := keystore.NewKeyService(keystore.FileStorage, wrongConfig)
	assert.Error(t, err, "Should error when using wrong config type")

	_, err = keystore.NewKeyService(keystore.FileStorage, nil)
	assert.Error(t, err, "Should error when using nil config")
}

func TestLocalFileKeyService_DeleteAndList(t *testing.T) {
	t.Parallel()

	filePath := tempFilePath()
	defer os.Remove(filePath) // This will clean up the file regardless of test outcome

	config := keystore.FileStorageConfig{
		FilePath: filePath,
	}

	service, err := keystore.NewKeyService(keystore.FileStorage, config)
	assert.NoError(t, err, "Failed to create key service")

	ctx := context.Background()

	// Initially, there should be no keys
	keys, err := service.ListKeys(ctx)
	assert.NoError(t, err, "ListKeys failed")
	assert.Empty(t, keys, "Initially there should be no keys")

	// Create keys with a test prefix for identification
	var testKeyIDs []string

	for i := 1; i <= 3; i++ {
		kid := fmt.Sprintf("test-key-%d", i)
		testKeyIDs = append(testKeyIDs, kid)

		jwk, err := joseutil.GenerateJWK("RS256", "sig", kid)
		assert.NoError(t, err, "GenerateJWK failed")

		err = service.SaveKey(ctx, jwk.KID, jwk)
		assert.NoError(t, err, "SaveKey failed")
	}

	// Now we should have 3 keys
	keys, err = service.ListKeys(ctx)
	assert.NoError(t, err, "ListKeys failed")
	assert.Len(t, keys, 3, "Should have 3 keys")
	assert.Contains(t, keys, "test-key-1", "Should contain test-key-1")
	assert.Contains(t, keys, "test-key-2", "Should contain test-key-2")
	assert.Contains(t, keys, "test-key-3", "Should contain test-key-3")

	// Delete one key
	err = service.DeleteKey(ctx, "test-key-2")
	assert.NoError(t, err, "DeleteKey failed")

	// Now we should have 2 keys
	keys, err = service.ListKeys(ctx)
	assert.NoError(t, err, "ListKeys failed")
	assert.Len(t, keys, 2, "Should have 2 keys")
	assert.Contains(t, keys, "test-key-1", "Should contain test-key-1")
	assert.Contains(t, keys, "test-key-3", "Should contain test-key-3")
	assert.NotContains(t, keys, "test-key-2", "Should not contain test-key-2")

	// Delete non-existent key should fail
	err = service.DeleteKey(ctx, "non-existent")
	assert.Error(t, err, "DeleteKey should fail for non-existent key")

	// Clean up remaining test keys
	for _, kid := range testKeyIDs {
		_ = service.DeleteKey(ctx, kid) // Ignore errors during cleanup
	}
}
