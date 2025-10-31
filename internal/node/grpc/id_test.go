// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpc_test

import (
	"errors"
	"fmt"
	"testing"

	nodeapi "github.com/agntcy/identity/api/server/agntcy/identity/node/v1alpha1"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	idtypes "github.com/agntcy/identity/internal/core/id/types"
	"github.com/agntcy/identity/internal/node/grpc"
	grpctesting "github.com/agntcy/identity/internal/node/grpc/testing"
	nodemocks "github.com/agntcy/identity/internal/node/mocks"
	"github.com/agntcy/identity/internal/pkg/errutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
)

var errIdUnexpected = errors.New("failed")

func TestIdService_Generate(t *testing.T) {
	t.Parallel()

	t.Run("should generate an ID successfully", func(t *testing.T) {
		t.Parallel()

		resolverMetadata := &idtypes.ResolverMetadata{
			ID: uuid.NewString(),
		}

		idSrv := nodemocks.NewIdService(t)
		idSrv.EXPECT().
			Generate(t.Context(), mock.Anything, mock.Anything).
			Return(resolverMetadata, nil)

		sut := grpc.NewIdService(idSrv)

		resp, err := sut.Generate(t.Context(), &nodeapi.GenerateRequest{})

		assert.NoError(t, err)
		assert.Equal(t, resolverMetadata.ID, resp.ResolverMetadata.GetId())
	})

	t.Run("should propagate error when core service fails", func(t *testing.T) {
		t.Parallel()

		idSrv := nodemocks.NewIdService(t)
		idSrv.EXPECT().
			Generate(t.Context(), mock.Anything, mock.Anything).
			Return(nil, errIdUnexpected)

		sut := grpc.NewIdService(idSrv)

		_, err := sut.Generate(t.Context(), &nodeapi.GenerateRequest{})

		assert.ErrorIs(t, err, errIdUnexpected)
	})
}

func TestIdService_Resolve(t *testing.T) {
	t.Parallel()

	t.Run("should resolve ID successfully", func(t *testing.T) {
		t.Parallel()

		idToResolve := uuid.NewString()

		resolverMetadata := &idtypes.ResolverMetadata{ID: idToResolve}

		idSrv := nodemocks.NewIdService(t)
		idSrv.EXPECT().
			Resolve(t.Context(), idToResolve).
			Return(resolverMetadata, nil)

		sut := grpc.NewIdService(idSrv)

		resp, err := sut.Resolve(t.Context(), &nodeapi.ResolveRequest{Id: idToResolve})

		assert.NoError(t, err)
		assert.Equal(t, resolverMetadata.ID, resp.ResolverMetadata.GetId())
	})

	t.Run("should return not found when ID is not resolved", func(t *testing.T) {
		t.Parallel()

		invalidID := uuid.NewString()

		idSrv := nodemocks.NewIdService(t)
		idSrv.EXPECT().
			Resolve(t.Context(), invalidID).
			Return(nil, errutil.ErrInfo(
				errtypes.ERROR_REASON_RESOLVER_METADATA_NOT_FOUND,
				"not found",
				nil,
			))

		sut := grpc.NewIdService(idSrv)

		_, err := sut.Resolve(t.Context(), &nodeapi.ResolveRequest{Id: invalidID})

		assert.Error(t, err)
		grpctesting.AssertGrpcError(
			t,
			err,
			codes.NotFound,
			fmt.Sprintf("not found (reason: %s)", errtypes.ERROR_REASON_RESOLVER_METADATA_NOT_FOUND),
		)
	})

	t.Run("should propagate error when core service fails", func(t *testing.T) {
		t.Parallel()

		idSrv := nodemocks.NewIdService(t)
		idSrv.EXPECT().
			Resolve(t.Context(), mock.Anything).
			Return(nil, errIdUnexpected)

		sut := grpc.NewIdService(idSrv)

		_, err := sut.Resolve(t.Context(), &nodeapi.ResolveRequest{})

		assert.ErrorIs(t, err, errIdUnexpected)
	})
}
