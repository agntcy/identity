// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package node_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	errcore "github.com/agntcy/identity/internal/core/errors"
	issuermocks "github.com/agntcy/identity/internal/core/issuer/mocks"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	"github.com/agntcy/identity/internal/core/issuer/verification"
	verifmocks "github.com/agntcy/identity/internal/core/issuer/verification/mocks"
	verificationtesting "github.com/agntcy/identity/internal/core/issuer/verification/testing"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/node"
	jwktype "github.com/agntcy/identity/pkg/jwk"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRegisterIssuer_Should_Not_Register_Same_Issuer_Twice(t *testing.T) {
	t.Parallel()

	pubKey, _ := generatePubKey()
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
		PublicKey:    pubKey,
	}

	verficationSrv := verifmocks.NewService(t)
	verficationSrv.EXPECT().
		Verify(t.Context(), issuer, mock.Anything).
		Return(&verification.Result{
			Issuer:   issuer,
			Verified: true,
		}, nil)

	issuerRepo := issuermocks.NewRepository(t)
	issuerRepo.EXPECT().GetIssuer(t.Context(), issuer.CommonName).Return(issuer, nil)
	sut := node.NewIssuerService(issuerRepo, verficationSrv)

	proof := &vctypes.Proof{
		Type:       "JWT",
		ProofValue: "",
	}

	err := sut.Register(t.Context(), issuer, proof)
	assert.Error(t, err)
}

func TestRegisterIssuer_Should_Register_Verified_Issuer(t *testing.T) {
	t.Parallel()

	pubKey, _ := generatePubKey()
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
		PublicKey:    pubKey,
	}

	verficationSrv := verifmocks.NewService(t)
	verficationSrv.EXPECT().
		Verify(t.Context(), issuer, mock.Anything).
		Return(&verification.Result{
			Issuer:   issuer,
			Verified: true,
		}, nil)

	issuerRepo := issuermocks.NewRepository(t)
	issuerRepo.EXPECT().CreateIssuer(t.Context(), issuer).Return(issuer, nil)
	issuerRepo.EXPECT().GetIssuer(t.Context(), issuer.CommonName).Return(nil, errcore.ErrResourceNotFound)
	sut := node.NewIssuerService(issuerRepo, verficationSrv)

	proof := &vctypes.Proof{
		Type:       "JWT",
		ProofValue: "",
	}

	// Register once
	err := sut.Register(t.Context(), issuer, proof)
	assert.NoError(t, err)
	assert.Equal(t, issuer.Verified, true)
}

func TestRegisterIssuer_Should_Register_Unverified_Issuer(t *testing.T) {
	t.Parallel()

	pubKey, _ := generatePubKey()
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
		PublicKey:    pubKey,
	}
	verficationSrv := verifmocks.NewService(t)
	verficationSrv.EXPECT().
		Verify(t.Context(), issuer, mock.Anything).
		Return(&verification.Result{
			Issuer:   issuer,
			Verified: false,
		}, nil)

	issuerRepo := issuermocks.NewRepository(t)
	issuerRepo.EXPECT().CreateIssuer(t.Context(), issuer).Return(issuer, nil)
	issuerRepo.EXPECT().GetIssuer(t.Context(), issuer.CommonName).Return(nil, errcore.ErrResourceNotFound)
	sut := node.NewIssuerService(issuerRepo, verficationSrv)

	proof := &vctypes.Proof{
		Type:       "JWT",
		ProofValue: "",
	}

	// Register once
	err := sut.Register(t.Context(), issuer, proof)
	assert.NoError(t, err)
	assert.Equal(t, issuer.Verified, false)
}

func generatePubKey() (*jwktype.Jwk, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pubkey, err := jwk.PublicRawKeyOf(pk)
	if err != nil {
		return nil, err
	}

	key, err := jwk.Import(pubkey)
	if err != nil {
		return nil, err
	}

	err = key.Set(jwk.AlgorithmKey, jwa.RS256())
	if err != nil {
		return nil, err
	}

	keyAsJson, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	var k jwktype.Jwk

	err = json.Unmarshal(keyAsJson, &k)
	if err != nil {
		return nil, err
	}

	return &k, nil
}
