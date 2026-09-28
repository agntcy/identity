// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package joseutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/agntcy/identity/pkg/jwk"
	"github.com/google/uuid"
)

const (
	rsaBits256 = 2048
	rsaBits384 = 3072
	rsaBits512 = 4096
	KeyTypeRSA = "RSA"

	// The RSASSA-PKCS1-v1_5 signature algorithms supported for key generation,
	// signing and verification.
	AlgRS256 = "RS256"
	AlgRS384 = "RS384"
	AlgRS512 = "RS512"
)

func GenerateJWK(alg, use, id string) (*jwk.Jwk, error) {
	if id == "" {
		id = uuid.NewString()
	}

	switch alg {
	case AlgRS256, AlgRS384, AlgRS512:
		return generateRSAJWK(alg, use, id)
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func generateRSAJWK(alg, use, id string) (*jwk.Jwk, error) {
	bits := map[string]int{
		AlgRS256: rsaBits256,
		AlgRS384: rsaBits384,
		AlgRS512: rsaBits512,
	}[alg]

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return &jwk.Jwk{
		KID: id,
		ALG: alg,
		KTY: KeyTypeRSA,
		USE: use,
		N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
		D:   base64.RawURLEncoding.EncodeToString(privateKey.D.Bytes()),
		P:   base64.RawURLEncoding.EncodeToString(privateKey.Primes[0].Bytes()),
		Q:   base64.RawURLEncoding.EncodeToString(privateKey.Primes[1].Bytes()),
		DP:  base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Dp.Bytes()),
		DQ:  base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Dq.Bytes()),
		QI:  base64.RawURLEncoding.EncodeToString(privateKey.Precomputed.Qinv.Bytes()),
	}, nil
}
