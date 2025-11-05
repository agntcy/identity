// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpc_test

import (
	"errors"
	"testing"

	sdkapi "github.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1"
	nodeapi "github.com/agntcy/identity/api/server/agntcy/identity/node/v1alpha1"
	"github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/node/grpc"
	"github.com/agntcy/identity/internal/node/grpc/converters"
	nodemocks "github.com/agntcy/identity/internal/node/mocks"
	"github.com/agntcy/identity/internal/pkg/ptrutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var errVcUnexpected = errors.New("failed")

func TestVcService_Publish(t *testing.T) {
	t.Parallel()

	t.Run("should publish Verifiable Credential successfully", func(t *testing.T) {
		t.Parallel()

		vc := sdkapi.EnvelopedCredential{
			EnvelopeType: ptrutil.Ptr(sdkapi.CredentialEnvelopeType_CREDENTIAL_ENVELOPE_TYPE_JOSE),
			Value:        ptrutil.Ptr(uuid.NewString()),
		}

		vcSrv := nodemocks.NewVerifiableCredentialService(t)
		vcSrv.EXPECT().
			Publish(t.Context(), converters.ToEnvelopedCredential(&vc), mock.Anything).
			Return(nil)

		sut := grpc.NewVcService(vcSrv)

		_, err := sut.Publish(t.Context(), &nodeapi.PublishRequest{
			Vc:    &vc,
			Proof: nil,
		})

		assert.NoError(t, err)
	})

	t.Run("should propagate error when core service fails", func(t *testing.T) {
		t.Parallel()

		vcSrv := nodemocks.NewVerifiableCredentialService(t)
		vcSrv.EXPECT().
			Publish(t.Context(), mock.Anything, mock.Anything).
			Return(errVcUnexpected)

		sut := grpc.NewVcService(vcSrv)

		_, err := sut.Publish(t.Context(), &nodeapi.PublishRequest{
			Vc:    &sdkapi.EnvelopedCredential{},
			Proof: nil,
		})

		assert.ErrorIs(t, err, errVcUnexpected)
	})
}

func TestVcService_Verify(t *testing.T) {
	t.Parallel()

	t.Run("should verify Verifiable Credential successfully", func(t *testing.T) {
		t.Parallel()

		vc := &sdkapi.EnvelopedCredential{
			EnvelopeType: ptrutil.Ptr(sdkapi.CredentialEnvelopeType_CREDENTIAL_ENVELOPE_TYPE_JOSE),
			Value:        ptrutil.Ptr(uuid.NewString()),
		}

		expectedResult := &types.VerificationResult{
			Status:     true,
			Controller: uuid.NewString(),
		}

		vcSrv := nodemocks.NewVerifiableCredentialService(t)
		vcSrv.EXPECT().
			Verify(t.Context(), converters.ToEnvelopedCredential(vc)).
			Return(expectedResult, nil)

		sut := grpc.NewVcService(vcSrv)

		actualResult, err := sut.Verify(t.Context(), &nodeapi.VerifyRequest{Vc: vc})

		assert.NoError(t, err)
		assert.Equal(t, expectedResult.Status, actualResult.GetStatus())
		assert.Equal(t, expectedResult.Controller, actualResult.GetController())
	})

	t.Run("should propagate error when core service fails", func(t *testing.T) {
		t.Parallel()

		vcSrv := nodemocks.NewVerifiableCredentialService(t)
		vcSrv.EXPECT().
			Verify(t.Context(), mock.Anything).
			Return(nil, errVcUnexpected)

		sut := grpc.NewVcService(vcSrv)

		_, err := sut.Verify(t.Context(), &nodeapi.VerifyRequest{Vc: &sdkapi.EnvelopedCredential{}})

		assert.ErrorIs(t, err, errVcUnexpected)
	})
}

func TestVcService_GetWellKnown(t *testing.T) {
	t.Parallel()

	t.Run("should get well-known Verifiable Credentials for an id successfully", func(t *testing.T) {
		t.Parallel()

		resolverMetadataID := uuid.NewString()
		expectedResult := []*types.EnvelopedCredential{
			{
				Value: uuid.NewString(),
			},
			{
				Value: uuid.NewString(),
			},
		}

		vcSrv := nodemocks.NewVerifiableCredentialService(t)
		vcSrv.EXPECT().
			GetVcs(t.Context(), resolverMetadataID).
			Return(expectedResult, nil)

		sut := grpc.NewVcService(vcSrv)

		actualResult, err := sut.GetWellKnown(t.Context(), &nodeapi.GetVcWellKnownRequest{
			Id: resolverMetadataID,
		})

		assert.NoError(t, err)

		for idx := range expectedResult {
			assert.Equal(t, expectedResult[idx].Value, actualResult.Vcs[idx].GetValue())
		}
	})

	t.Run("should propagate error when core service fails", func(t *testing.T) {
		t.Parallel()

		vcSrv := nodemocks.NewVerifiableCredentialService(t)
		vcSrv.EXPECT().
			GetVcs(t.Context(), mock.Anything).
			Return(nil, errVcUnexpected)

		sut := grpc.NewVcService(vcSrv)

		_, err := sut.GetWellKnown(t.Context(), &nodeapi.GetVcWellKnownRequest{
			Id: uuid.NewString(),
		})

		assert.ErrorIs(t, err, errVcUnexpected)
	})
}

func TestVcService_Revoke(t *testing.T) {
	t.Parallel()

	t.Run("should revoke a Verifiable Credential successfully", func(t *testing.T) {
		t.Parallel()

		vc := &sdkapi.EnvelopedCredential{
			EnvelopeType: ptrutil.Ptr(sdkapi.CredentialEnvelopeType_CREDENTIAL_ENVELOPE_TYPE_JOSE),
			Value:        ptrutil.Ptr(uuid.NewString()),
		}

		vcSrv := nodemocks.NewVerifiableCredentialService(t)
		vcSrv.EXPECT().
			Revoke(t.Context(), converters.ToEnvelopedCredential(vc), mock.Anything).
			Return(nil)

		sut := grpc.NewVcService(vcSrv)

		_, err := sut.Revoke(t.Context(), &nodeapi.RevokeRequest{
			Vc:    vc,
			Proof: nil,
		})

		assert.NoError(t, err)
	})

	t.Run("should propagate error when core service fails", func(t *testing.T) {
		t.Parallel()

		vcSrv := nodemocks.NewVerifiableCredentialService(t)
		vcSrv.EXPECT().
			Revoke(t.Context(), mock.Anything, mock.Anything).
			Return(errVcUnexpected)

		sut := grpc.NewVcService(vcSrv)

		_, err := sut.Revoke(t.Context(), &nodeapi.RevokeRequest{
			Vc:    &sdkapi.EnvelopedCredential{},
			Proof: nil,
		})

		assert.ErrorIs(t, err, errVcUnexpected)
	})
}
