// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package joseutil

import (
	"encoding/json"
	"errors"
	"fmt"

	jwktype "github.com/agntcy/identity/pkg/jwk"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Sign creates a JWS signature for the provided payload using the specified key
func Sign(privateJwk *jwktype.Jwk, payload []byte) ([]byte, error) {
	if privateJwk == nil {
		return nil, errors.New("private key is nil")
	}

	// Convert our custom JWK to the jwx library's JWK
	key, err := customJwkToLibraryJwk(privateJwk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key: %w", err)
	}

	// Determine the signing algorithm from the JWK
	alg, err := determineAlgorithm(privateJwk.ALG)
	if err != nil {
		return nil, err
	}

	// Create and sign
	signed, err := jws.Sign(payload, jws.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	return signed, nil
}

// Verify checks if a JWS signature is valid using the specified public key
func Verify(publicJwk *jwktype.Jwk, signedPayload []byte) ([]byte, error) {
	if publicJwk == nil {
		return nil, errors.New("public key is nil")
	}

	// Convert our custom JWK to the jwx library's JWK
	key, err := customJwkToLibraryJwk(publicJwk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key: %w", err)
	}

	// Determine the signing algorithm from the JWK
	alg, err := determineAlgorithm(publicJwk.ALG)
	if err != nil {
		return nil, err
	}

	// Verify the signature
	payload, err := jws.Verify(signedPayload, jws.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return payload, nil
}

// customJwkToLibraryJwk converts our custom JWK type to the jwx library's JWK
func customJwkToLibraryJwk(jwkObj *jwktype.Jwk) (jwk.Key, error) {
	// Convert to a JSON representation first
	jsonBytes, err := json.Marshal(jwkObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	key, err := jwk.ParseKey(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	return key, nil
}

// determineAlgorithm maps algorithm string to jwa.SignatureAlgorithm
func determineAlgorithm(algStr string) (jwa.SignatureAlgorithm, error) {
	switch algStr {
	case AlgRS256:
		return jwa.RS256(), nil
	case AlgRS384:
		return jwa.RS384(), nil
	case AlgRS512:
		return jwa.RS512(), nil
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported algorithm: %s", algStr)
	}
}
