// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package node_test

import (
	"errors"
	"testing"

	errcore "github.com/agntcy/identity/internal/core/errors"
	errtesting "github.com/agntcy/identity/internal/core/errors/testing"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	idmocks "github.com/agntcy/identity/internal/core/id/mocks"
	idtypes "github.com/agntcy/identity/internal/core/id/types"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	verificationtesting "github.com/agntcy/identity/internal/core/issuer/verification/testing"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/node"
	nodemocks "github.com/agntcy/identity/internal/node/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGenerateID_Should_Not_Return_Errors(t *testing.T) {
	t.Parallel()

	id := "DUO-test"
	idRepo := idmocks.NewIdRepository(t)
	idRepo.EXPECT().ResolveID(t.Context(), id).Return(nil, errcore.ErrResourceNotFound)
	idRepo.EXPECT().
		CreateID(t.Context(), mock.Anything, mock.Anything).
		Return(&idtypes.ResolverMetadata{ID: id}, nil)

	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	idGen := nodemocks.NewIDGenerator(t)
	idGen.EXPECT().GenerateFromProof(t.Context(), mock.Anything).Return(id, issuer, nil)

	sut := node.NewIdService(idRepo, idGen)

	md, err := sut.Generate(t.Context(), issuer, &vctypes.Proof{Type: "JWT"})

	assert.NoError(t, err)
	assert.Equal(t, id, md.ID)
}

func TestGenerateID_Should_Not_Return_Error_With_Self_Provider(t *testing.T) {
	t.Parallel()

	id := node.SelfScheme + "test"
	idRepo := idmocks.NewIdRepository(t)
	idRepo.EXPECT().ResolveID(t.Context(), id).Return(nil, errcore.ErrResourceNotFound)
	idRepo.EXPECT().
		CreateID(t.Context(), mock.Anything, mock.Anything).
		Return(&idtypes.ResolverMetadata{ID: id}, nil)

	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	idGen := nodemocks.NewIDGenerator(t)
	idGen.EXPECT().GenerateFromProof(t.Context(), mock.Anything).Return(id, issuer, nil)

	sut := node.NewIdService(idRepo, idGen)

	md, err := sut.Generate(t.Context(), issuer, &vctypes.Proof{Type: "JWT"})

	assert.NoError(t, err)
	assert.Equal(t, id, md.ID)
}

func TestGenerateID_Should_Return_When_GenerateFromProof_Fails(t *testing.T) {
	t.Parallel()

	idGen := nodemocks.NewIDGenerator(t)
	idGen.EXPECT().GenerateFromProof(t.Context(), mock.Anything).Return("", nil, errors.New("failed"))

	sut := node.NewIdService(nil, idGen)

	_, err := sut.Generate(t.Context(), nil, &vctypes.Proof{Type: "JWT"})

	assert.ErrorContains(t, err, "failed")
}

func TestGenerateID_Should_Return_Invalid_Issuer_Error(t *testing.T) {
	t.Parallel()

	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	idGen := nodemocks.NewIDGenerator(t)
	idGen.EXPECT().GenerateFromProof(t.Context(), mock.Anything).Return("", issuer, nil)

	idRepo := idmocks.NewIdRepository(t)
	idRepo.EXPECT().ResolveID(t.Context(), mock.Anything).Return(nil, errcore.ErrResourceNotFound)
	sut := node.NewIdService(idRepo, idGen)

	invalidIssuer := &issuertypes.Issuer{
		CommonName: "INVALID",
	}

	_, err := sut.Generate(t.Context(), invalidIssuer, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_ISSUER)
}

func TestGenerateID_Should_Return_ID_Already_Exists_Error(t *testing.T) {
	t.Parallel()

	existingMD := &idtypes.ResolverMetadata{ID: "DUO-" + uuid.NewString()}

	idRepo := idmocks.NewIdRepository(t)
	idRepo.EXPECT().ResolveID(t.Context(), existingMD.ID).Return(existingMD, nil)

	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	idGen := nodemocks.NewIDGenerator(t)
	idGen.EXPECT().GenerateFromProof(t.Context(), mock.Anything).Return(existingMD.ID, issuer, nil)

	sut := node.NewIdService(idRepo, idGen)

	_, err := sut.Generate(t.Context(), nil, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_ID_ALREADY_REGISTERED)
}

func TestResolveID_Should_Return_Resolver_Metadata(t *testing.T) {
	t.Parallel()

	md := &idtypes.ResolverMetadata{
		ID: "SOME_ID",
	}

	idRepo := idmocks.NewIdRepository(t)
	idRepo.EXPECT().ResolveID(t.Context(), md.ID).Return(md, nil)
	sut := node.NewIdService(idRepo, nil)

	_, err := sut.Resolve(t.Context(), md.ID)

	assert.NoError(t, err)
}

func TestResolveID_Should_Return_Resolver_Metadata_Not_Found_Error(t *testing.T) {
	t.Parallel()

	id := "SOME_ID"
	idRepo := idmocks.NewIdRepository(t)
	idRepo.EXPECT().ResolveID(t.Context(), id).Return(nil, errcore.ErrResourceNotFound)
	sut := node.NewIdService(idRepo, nil)

	_, err := sut.Resolve(t.Context(), id)

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_RESOLVER_METADATA_NOT_FOUND)
}
