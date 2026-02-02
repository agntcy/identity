// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package node_test

import (
	"context"
	"errors"
	"testing"

	errcore "github.com/agntcy/identity/internal/core/errors"
	errtesting "github.com/agntcy/identity/internal/core/errors/testing"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	idmocks "github.com/agntcy/identity/internal/core/id/mocks"
	idtypes "github.com/agntcy/identity/internal/core/id/types"
	issuertesting "github.com/agntcy/identity/internal/core/issuer/testing"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	issuerverif "github.com/agntcy/identity/internal/core/issuer/verification"
	verificationtesting "github.com/agntcy/identity/internal/core/issuer/verification/testing"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/node"
	"github.com/agntcy/identity/pkg/jwk"
	"github.com/agntcy/identity/pkg/oidc"
	oidctesting "github.com/agntcy/identity/pkg/oidc/testing"
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

	issuerRepo := issuertesting.NewFakeIssuerRepository()
	jwt := &oidc.ParsedJWT{
		Provider: oidc.DuoProviderName,
		Claims: &oidc.Claims{
			Issuer:  "http://" + verificationtesting.ValidProofIssuer,
			Subject: "test",
		},
		CommonName: verificationtesting.ValidProofIssuer,
	}
	idGen := node.NewIDGenerator(
		issuerverif.NewService(
			oidctesting.NewFakeParser(jwt, nil),
			issuerRepo,
		))
	sut := node.NewIdService(idRepo, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)

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

	issuerRepo := issuertesting.NewFakeIssuerRepository()
	jwt := &oidc.ParsedJWT{
		Provider: oidc.SelfProviderName,
		Claims: &oidc.Claims{
			Issuer:  verificationtesting.ValidProofIssuer,
			Subject: "test",
		},
		CommonName: verificationtesting.ValidProofIssuer,
	}
	idGen := node.NewIDGenerator(
		issuerverif.NewService(
			oidctesting.NewFakeParser(jwt, nil),
			issuerRepo,
		),
	)
	sut := node.NewIdService(idRepo, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)

	md, err := sut.Generate(t.Context(), issuer, &vctypes.Proof{Type: "JWT"})

	assert.NoError(t, err)
	assert.Equal(t, id, md.ID)
}

func TestGenerateID_Should_Return_Error_With_Idp_And_Self_Proof(t *testing.T) {
	t.Parallel()

	idRepo := idmocks.NewIdRepository(t)
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	jwt := &oidc.ParsedJWT{
		Provider: oidc.SelfProviderName,
		Claims: &oidc.Claims{
			Issuer:  verificationtesting.ValidProofIssuer,
			Subject: "test",
		},
		CommonName: verificationtesting.ValidProofIssuer,
	}
	idGen := node.NewIDGenerator(
		issuerverif.NewService(
			oidctesting.NewFakeParser(jwt, nil),
			issuerRepo,
		),
	)
	sut := node.NewIdService(idRepo, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
		Verified:     true,
		PublicKey:    &jwk.Jwk{},
		AuthType:     issuertypes.ISSUER_AUTH_TYPE_IDP,
	}
	_, _ = issuerRepo.CreateIssuer(context.Background(), issuer)

	_, err := sut.Generate(context.Background(), issuer, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_IDP_REQUIRED)
}

func TestGenerateID_Should_Return_Invalid_Proof_If_Empty(t *testing.T) {
	t.Parallel()

	oidcParser := oidctesting.NewFakeParser(&oidc.ParsedJWT{}, nil)
	idGen := node.NewIDGenerator(issuerverif.NewService(oidcParser, nil))
	sut := node.NewIdService(nil, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}

	_, err := sut.Generate(context.Background(), issuer, nil)

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
}

func TestGenerateID_Should_Return_Invalid_Proof_Error(t *testing.T) {
	t.Parallel()

	idGen := node.NewIDGenerator(
		issuerverif.NewService(
			oidctesting.NewFakeParser(nil, errors.New("")),
			nil,
		),
	)
	sut := node.NewIdService(nil, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}

	_, err := sut.Generate(context.Background(), issuer, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
}

func TestGenerateID_Should_Return_Invalid_Issuer_Error(t *testing.T) {
	t.Parallel()

	issuerRepo := issuertesting.NewFakeIssuerRepository()
	jwt := &oidc.ParsedJWT{
		Provider: oidc.DuoProviderName,
		Claims: &oidc.Claims{
			Issuer:  "http://" + verificationtesting.ValidProofIssuer,
			Subject: "test",
		},
		CommonName: verificationtesting.ValidProofIssuer,
	}
	idGen := node.NewIDGenerator(
		issuerverif.NewService(
			oidctesting.NewFakeParser(jwt, nil),
			issuerRepo,
		),
	)
	idRepo := idmocks.NewIdRepository(t)
	idRepo.EXPECT().ResolveID(t.Context(), mock.Anything).Return(nil, errcore.ErrResourceNotFound)
	sut := node.NewIdService(idRepo, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)
	invalidIssuer := &issuertypes.Issuer{
		CommonName: "INVALID",
	}

	_, err := sut.Generate(t.Context(), invalidIssuer, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_ISSUER)
}

func TestGenerateID_Should_Return_Unregistred_Issuer_Error(t *testing.T) {
	t.Parallel()

	issuerRepo := issuertesting.NewFakeIssuerRepository()
	jwt := &oidc.ParsedJWT{
		Provider: oidc.DuoProviderName,
		Claims:   &oidc.Claims{Subject: "test"},
	}
	idGen := node.NewIDGenerator(
		issuerverif.NewService(
			oidctesting.NewFakeParser(jwt, nil),
			issuerRepo,
		),
	)
	sut := node.NewIdService(nil, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}

	_, err := sut.Generate(context.Background(), issuer, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_ISSUER_NOT_REGISTERED)
}

func TestGenerateID_Should_Return_ID_Already_Exists_Error(t *testing.T) {
	t.Parallel()

	claims := &oidc.Claims{
		Issuer:  "http://" + verificationtesting.ValidProofIssuer,
		Subject: "test",
	}
	existingMD := &idtypes.ResolverMetadata{ID: "DUO-" + claims.Subject}

	idRepo := idmocks.NewIdRepository(t)
	idRepo.EXPECT().ResolveID(t.Context(), existingMD.ID).Return(existingMD, nil)

	issuerRepo := issuertesting.NewFakeIssuerRepository()

	jwt := &oidc.ParsedJWT{
		Provider:   oidc.DuoProviderName,
		Claims:     claims,
		CommonName: verificationtesting.ValidProofIssuer,
	}
	idGen := node.NewIDGenerator(
		issuerverif.NewService(
			oidctesting.NewFakeParser(jwt, nil),
			issuerRepo,
		),
	)
	sut := node.NewIdService(idRepo, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)

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
