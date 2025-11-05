// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package joseutil_test

import (
	"testing"

	"github.com/agntcy/identity/pkg/joseutil"
	"github.com/agntcy/identity/pkg/jwk"
	"github.com/stretchr/testify/assert"
)

func TestGenerateAndValidateKeys(t *testing.T) {
	t.Parallel()

	algorithms := []string{"RS256", "RS384", "RS512"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()

			priv, err := joseutil.GenerateJWK(alg, "sig", "")
			assert.NoError(t, err, "GenerateJWK failed for %s", alg)

			// Validate public key (should pass)
			err = joseutil.ValidatePubKey(priv.PublicKey())
			assert.NoError(t, err, "ValidatePubKey failed for %s", alg)

			// Validate private key (should pass)
			err = joseutil.ValidatePrivKey(priv)
			assert.NoError(t, err, "ValidatePrivKey failed for %s", alg)

			// Public key with private fields should fail
			err = joseutil.ValidatePubKey(priv)
			assert.Error(
				t,
				err,
				"ValidatePubKey should fail if private fields are present for %s",
				alg,
			)
		})
	}
}

func TestValidatePubKey_NilOrEmptyFields(t *testing.T) {
	t.Parallel()

	// Test nil Jwk pointer
	var nilJwk *jwk.Jwk

	err := joseutil.ValidatePubKey(nilJwk)
	assert.Error(t, err, "ValidatePubKey should fail if Jwk is nil")

	// Test Jwk with missing required fields for RSA
	pub := &jwk.Jwk{KTY: "RSA"}
	err = joseutil.ValidatePubKey(pub)
	assert.Error(t, err, "ValidatePubKey should fail if required RSA fields are missing")
}

func TestGenerateJWK_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	_, err := joseutil.GenerateJWK("unsupported-alg", "sig", "")
	assert.Error(t, err, "Expected error for unsupported algorithm")
}

func TestSignAndVerify(t *testing.T) {
	t.Parallel()

	algorithms := []string{"RS256", "RS384", "RS512"}
	payload := []byte(`{"test":"data"}`)

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()

			// Generate a key pair
			priv, err := joseutil.GenerateJWK(alg, "sig", "")
			assert.NoError(t, err, "GenerateJWK failed")

			// Get the public key
			publicKey := priv.PublicKey()

			// Sign the payload with the private key
			signature, err := joseutil.Sign(priv, payload)
			assert.NoError(t, err, "Sign failed")
			assert.NotEmpty(t, signature, "Signature should not be empty")

			// Verify the signature with the public key
			verified, err := joseutil.Verify(publicKey, signature)
			assert.NoError(t, err, "Verification failed")
			assert.Equal(t, payload, verified, "Verified payload should match original")

			// Try to verify with an invalid signature
			invalidSig := append([]byte(nil), signature...)
			invalidSig[len(invalidSig)-1] ^= 0xFF // flip some bits
			_, err = joseutil.Verify(publicKey, invalidSig)
			assert.Error(t, err, "Verification should fail with invalid signature")
		})
	}
}

func TestSignAndVerifyErrors(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)

	// Generate a key
	priv, err := joseutil.GenerateJWK("RS256", "sig", "")
	assert.NoError(t, err, "GenerateJWK failed")

	publicKey := priv.PublicKey()

	// Test nil keys
	_, err = joseutil.Sign(nil, payload)
	assert.Error(t, err, "Sign should fail with nil key")

	_, err = joseutil.Verify(nil, payload)
	assert.Error(t, err, "Verify should fail with nil key")

	// Test unsupported algorithm
	priv.ALG = "UNSUPPORTED"
	_, err = joseutil.Sign(priv, payload)
	assert.Error(t, err, "Sign should fail with unsupported algorithm")

	publicKey.ALG = "UNSUPPORTED"
	_, err = joseutil.Verify(publicKey, payload)
	assert.Error(t, err, "Verify should fail with unsupported algorithm")
}
