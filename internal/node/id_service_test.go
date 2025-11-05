// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package node_test

import (
	"context"
	"errors"
	"testing"

	errtesting "github.com/agntcy/identity/internal/core/errors/testing"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	idtesting "github.com/agntcy/identity/internal/core/id/testing"
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
)

func TestGenerateID_Should_Not_Return_Errors(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
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
	_, _ = issuerRepo.CreateIssuer(context.Background(), issuer)

	md, err := sut.Generate(context.Background(), issuer, &vctypes.Proof{Type: "JWT"})

	assert.NoError(t, err)
	assert.Equal(t, "DUO-test", md.ID)
}

func TestGenerateID_Should_Not_Return_Error_With_Self_Provider(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
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
	_, _ = issuerRepo.CreateIssuer(context.Background(), issuer)

	md, err := sut.Generate(context.Background(), issuer, &vctypes.Proof{Type: "JWT"})

	assert.NoError(t, err)
	assert.Equal(t, node.SelfScheme+"test", md.ID)
}

func TestGenerateID_Should_Return_Error_With_Idp_And_Self_Proof(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
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
	idRepo := idtesting.NewFakeIdRepository()
	sut := node.NewIdService(idRepo, idGen)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(context.Background(), issuer)
	invalidIssuer := &issuertypes.Issuer{
		CommonName: "INVALID",
	}

	_, err := sut.Generate(context.Background(), invalidIssuer, &vctypes.Proof{Type: "JWT"})

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

	idRepo := idtesting.NewFakeIdRepository()
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	claims := &oidc.Claims{
		Issuer:  "http://" + verificationtesting.ValidProofIssuer,
		Subject: "test",
	}
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
	_, _ = issuerRepo.CreateIssuer(context.Background(), issuer)
	_, _ = idRepo.CreateID(
		context.Background(),
		&idtypes.ResolverMetadata{ID: "DUO-" + claims.Subject},
		issuer,
	)

	_, err := sut.Generate(context.Background(), nil, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_ID_ALREADY_REGISTERED)
}

func TestResolveID_Should_Return_Resolver_Metadata(t *testing.T) {
	t.Parallel()

	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}

	idRepo := idtesting.NewFakeIdRepository()
	sut := node.NewIdService(idRepo, nil)
	md := &idtypes.ResolverMetadata{
		ID: "SOME_ID",
	}
	_, _ = idRepo.CreateID(context.Background(), md, issuer)

	_, err := sut.Resolve(context.Background(), md.ID)

	assert.NoError(t, err)
}

func TestResolveID_Should_Return_Resolver_Metadata_Not_Found_Error(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
	sut := node.NewIdService(idRepo, nil)

	_, err := sut.Resolve(context.Background(), "SOME_ID")

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_RESOLVER_METADATA_NOT_FOUND)
}
