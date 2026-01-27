// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0
//go:build integration

package keystore_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/agntcy/identity/pkg/joseutil"
	"github.com/agntcy/identity/pkg/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupVaultService creates a new VaultKeyService with optional unique base path
func setupVaultService(
	t *testing.T,
	uniquePath bool,
) (keystore.KeyService, context.Context, []string) {
	t.Helper()

	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")
	vaultNamespace := os.Getenv("VAULT_NAMESPACE")

	require.NotEmpty(t, vaultAddr, "VAULT_ADDR environment variable must be set")
	require.NotEmpty(t, vaultToken, "VAULT_TOKEN environment variable must be set")
	require.NotEmpty(t, vaultNamespace, "VAULT_NAMESPACE environment variable must be set")

	basePath := "test-jwks"

	if uniquePath {
		uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
		basePath = "test-jwks-" + uniqueSuffix
	}

	config := keystore.VaultStorageConfig{
		Address:     vaultAddr,
		Token:       vaultToken,
		MountPath:   "secret",
		KeyBasePath: basePath,
		Namespace:   vaultNamespace,
	}

	service, err := keystore.NewKeyService(keystore.VaultStorage, config)
	require.NoError(t, err, "Failed to create key service")

	return service, context.Background(), []string{}
}

// createTestKeys creates multiple test keys and returns their IDs
func createTestKeys(
	t *testing.T,
	service keystore.KeyService,
	ctx context.Context,
	count int,
	prefix string,
) []string {
	t.Helper()

	var keyIDs []string

	for i := 1; i <= count; i++ {
		kid := fmt.Sprintf("%s-%d", prefix, i)
		keyIDs = append(keyIDs, kid)

		jwk, err := joseutil.GenerateJWK("RS256", "sig", kid)
		assert.NoError(t, err, "GenerateJWK failed")

		err = service.SaveKey(ctx, jwk.KID, jwk)
		assert.NoError(t, err, "SaveKey failed")
	}

	return keyIDs
}

// cleanupKeys removes the specified keys
func cleanupKeys(service keystore.KeyService, ctx context.Context, keyIDs []string) {
	for _, kid := range keyIDs {
		_ = service.DeleteKey(ctx, kid) // Best effort cleanup
	}
}

func TestVaultKeyService(t *testing.T) {
	t.Parallel()

	if os.Getenv("INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping Vault integration test. Set INTEGRATION_TESTS=true to run")
	}

	service, ctx, testKeyIDs := setupVaultService(t, false)

	// Create a unique key for this test
	uniqueSuffix := fmt.Sprintf("%d", time.Now().UnixNano())
	keyID := "test-vault-key-" + uniqueSuffix
	testKeyIDs = append(testKeyIDs, keyID)

	// Ensure cleanup
	defer cleanupKeys(service, ctx, testKeyIDs)

	// Generate test key
	priv, err := joseutil.GenerateJWK("RS256", "sig", keyID)
	require.NoError(t, err, "GenerateJWK failed")

	// Test saving
	err = service.SaveKey(ctx, priv.KID, priv)
	assert.NoError(t, err, "SaveKey failed")

	// Test retrieving public key
	pub, err := service.RetrievePubKey(ctx, priv.KID)
	if !assert.NoError(t, err, "RetrievePubKey failed") {
		t.FailNow()
	}

	// Verify public key structure
	t.Run("PublicKeyFields", func(t *testing.T) {
		// Verify public key doesn't contain private fields
		assert.Empty(t, pub.D, "PublicJWK should not contain private D field")
		assert.Empty(t, pub.P, "PublicJWK should not contain private P field")
		assert.Empty(t, pub.Q, "PublicJWK should not contain private Q field")

		// Verify public key contains correct public fields
		assert.Equal(t, priv.N, pub.N, "PublicJWK should contain correct N field")
		assert.Equal(t, priv.E, pub.E, "PublicJWK should contain correct E field")
	})

	// Test retrieving private key
	t.Run("PrivateKeyFields", func(t *testing.T) {
		gotPriv, err := service.RetrievePrivKey(ctx, priv.KID)
		assert.NoError(t, err, "RetrievePrivKey failed")

		// Add safety check to prevent nil pointer dereference
		if !assert.NotNil(t, gotPriv, "Retrieved private key should not be nil") {
			t.FailNow()
		}

		assert.Equal(t, priv.D, gotPriv.D, "Private key should contain correct D field")
		assert.Equal(t, priv.P, gotPriv.P, "Private key should contain correct P field")
		assert.Equal(t, priv.Q, gotPriv.Q, "Private key should contain correct Q field")
	})

	// Test non-existent key
	_, err = service.RetrievePubKey(ctx, "non-existent")
	assert.Error(t, err, "Should error for non-existent key")
}

func TestVaultKeyService_DeleteAndList(t *testing.T) {
	t.Parallel()

	if os.Getenv("INTEGRATION_TESTS") != "true" {
		t.Skip("Skipping Vault integration test. Set INTEGRATION_TESTS=true to run")
	}

	// Setup with a unique path to isolate this test
	service, ctx, _ := setupVaultService(t, true)

	// Track keys we create for cleanup
	testKeyIDs := createTestKeys(t, service, ctx, 3, "test-key")

	// Ensure cleanup
	defer cleanupKeys(service, ctx, testKeyIDs)

	// Test key listing
	t.Run("ListKeysAfterCreation", func(t *testing.T) {
		keys, err := service.ListKeys(ctx)
		assert.NoError(t, err, "ListKeys failed")
		assert.Len(t, keys, 3, "Should have 3 keys")

		for i := 1; i <= 3; i++ {
			expected := fmt.Sprintf("test-key-%d", i)
			assert.Contains(t, keys, expected, "Should contain %s", expected)
		}
	})

	// Test key deletion
	t.Run("DeleteKey", func(t *testing.T) {
		// Delete the middle key
		err := service.DeleteKey(ctx, "test-key-2")
		assert.NoError(t, err, "DeleteKey failed")

		// Verify key is gone
		keys, err := service.ListKeys(ctx)
		assert.NoError(t, err, "ListKeys failed")
		assert.Len(t, keys, 2, "Should have 2 keys after deletion")
		assert.Contains(t, keys, "test-key-1", "Should contain test-key-1")
		assert.Contains(t, keys, "test-key-3", "Should contain test-key-3")
		assert.NotContains(t, keys, "test-key-2", "Should not contain test-key-2")
	})

	// Test deleting non-existent key
	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		err := service.DeleteKey(ctx, "non-existent")
		assert.Error(t, err, "DeleteKey should fail for non-existent key")
	})
}
