// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpc_test

import (
	"errors"
	"testing"

	sdkapi "github.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1"
	nodeapi "github.com/agntcy/identity/api/server/agntcy/identity/node/v1alpha1"
	"github.com/agntcy/identity/internal/node/grpc"
	"github.com/agntcy/identity/internal/node/grpc/converters"
	nodemocks "github.com/agntcy/identity/internal/node/mocks"
	"github.com/agntcy/identity/pkg/jwk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var errIssuerUnexpected = errors.New("failed")

func TestIssuerService_Register(t *testing.T) {
	t.Parallel()

	t.Run("should register an issuer successfully", func(t *testing.T) {
		t.Parallel()

		issuerSrv := nodemocks.NewIssuerService(t)
		issuerSrv.EXPECT().Register(t.Context(), mock.Anything, mock.Anything).Return(nil)

		sut := grpc.NewIssuerService(issuerSrv)

		_, err := sut.Register(t.Context(), &nodeapi.RegisterIssuerRequest{
			Issuer: &sdkapi.Issuer{},
			Proof:  &sdkapi.Proof{},
		})

		assert.NoError(t, err)
	})

	t.Run("should propagate error when core service fails", func(t *testing.T) {
		t.Parallel()

		issuerSrv := nodemocks.NewIssuerService(t)
		issuerSrv.EXPECT().
			Register(t.Context(), mock.Anything, mock.Anything).
			Return(errIssuerUnexpected)

		sut := grpc.NewIssuerService(issuerSrv)

		_, err := sut.Register(t.Context(), &nodeapi.RegisterIssuerRequest{
			Issuer: &sdkapi.Issuer{},
			Proof:  &sdkapi.Proof{},
		})

		assert.ErrorIs(t, err, errIssuerUnexpected)
	})
}

func TestIssuerService_GetWellKnown(t *testing.T) {
	t.Parallel()

	t.Run("should get a well known document content successfully", func(t *testing.T) {
		t.Parallel()

		commonName := uuid.NewString()
		jwks := jwk.Jwks{Keys: []*jwk.Jwk{{KID: uuid.NewString()}}}

		issuerSrv := nodemocks.NewIssuerService(t)
		issuerSrv.EXPECT().GetJwks(t.Context(), commonName).Return(&jwks, nil)

		sut := grpc.NewIssuerService(issuerSrv)

		resp, err := sut.GetWellKnown(t.Context(), &nodeapi.GetIssuerWellKnownRequest{
			CommonName: commonName,
		})

		assert.NoError(t, err)
		assert.Equal(t, converters.FromJwks(&jwks), resp.GetJwks())
	})

	t.Run("should propagate error when core service fails", func(t *testing.T) {
		t.Parallel()

		issuerSrv := nodemocks.NewIssuerService(t)
		issuerSrv.EXPECT().
			GetJwks(t.Context(), mock.Anything).
			Return(nil, errIssuerUnexpected)

		sut := grpc.NewIssuerService(issuerSrv)

		_, err := sut.GetWellKnown(t.Context(), &nodeapi.GetIssuerWellKnownRequest{
			CommonName: uuid.NewString(),
		})

		assert.ErrorIs(t, err, errIssuerUnexpected)
	})
}
