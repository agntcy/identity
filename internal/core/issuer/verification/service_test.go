// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package verification_test

import (
	"errors"
	"testing"

	errcore "github.com/agntcy/identity/internal/core/errors"
	errtesting "github.com/agntcy/identity/internal/core/errors/testing"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	issuermocks "github.com/agntcy/identity/internal/core/issuer/mocks"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	issuerverif "github.com/agntcy/identity/internal/core/issuer/verification"
	verifmocks "github.com/agntcy/identity/internal/core/issuer/verification/mocks"
	veriftesting "github.com/agntcy/identity/internal/core/issuer/verification/testing"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestVerify_Should_Verify_Successfully(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		issuer           *issuertypes.Issuer
		jwt              *oidc.ParsedJWT
		expectedVerified bool
	}{
		"IdP issuer": {
			issuer: &issuertypes.Issuer{
				CommonName:   veriftesting.ValidProofIssuer,
				Organization: "Some Org",
			},
			jwt: &oidc.ParsedJWT{
				Provider: oidc.DuoProviderName,
				Claims: &oidc.Claims{
					Issuer:  "http://" + veriftesting.ValidProofIssuer,
					Subject: "test",
				},
				CommonName: veriftesting.ValidProofIssuer,
			},
			expectedVerified: true,
		},
		"Self issuer": {
			issuer: &issuertypes.Issuer{
				CommonName:   veriftesting.ValidProofIssuer,
				Organization: "Some Org",
			},
			jwt: &oidc.ParsedJWT{
				Provider: oidc.SelfProviderName,
				Claims: &oidc.Claims{
					Issuer:  veriftesting.ValidProofIssuer,
					Subject: "test",
				},
				CommonName: veriftesting.ValidProofIssuer,
			},
			expectedVerified: false,
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			t.Parallel()

			issuerRepo := issuermocks.NewRepository(t)

			jwtParser := verifmocks.NewParser(t)
			jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(tc.jwt, nil)
			jwtParser.EXPECT().VerifyJwt(t.Context(), tc.jwt).Return(nil)

			sut := issuerverif.NewService(jwtParser, issuerRepo)

			result, err := sut.Verify(t.Context(), tc.issuer, &vctypes.Proof{Type: "JWT"})

			assert.NoError(t, err)
			assert.Equal(t, tc.issuer, result.Issuer)
			assert.Equal(t, tc.expectedVerified, result.Verified)
		})
	}
}

func TestVerify_Should_Fail(t *testing.T) {
	t.Parallel()

	t.Run("when proof is nil", func(t *testing.T) {
		t.Parallel()

		sut := issuerverif.NewService(nil, nil)

		_, err := sut.Verify(t.Context(), nil, nil)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
		assert.ErrorContains(t, err, "a proof is required")
	})

	t.Run("when proof is not JWT", func(t *testing.T) {
		t.Parallel()

		invalidProof := &vctypes.Proof{Type: "INVALID_TYPE"}
		sut := issuerverif.NewService(nil, nil)

		_, err := sut.Verify(t.Context(), nil, invalidProof)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_UNSUPPORTED_PROOF)
	})

	t.Run("when proof JWT is invalid", func(t *testing.T) {
		t.Parallel()

		proof := &vctypes.Proof{Type: "JWT", ProofValue: "INVALID_JWT"}

		jwtParser := verifmocks.NewParser(t)
		jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(nil, errors.New("invalid jwt"))

		sut := issuerverif.NewService(jwtParser, nil)

		_, err := sut.Verify(t.Context(), nil, proof)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
		assert.ErrorContains(t, err, "invalid jwt")
	})

	t.Run("when proof JWT verification fails", func(t *testing.T) {
		t.Parallel()

		proof := &vctypes.Proof{Type: "JWT", ProofValue: "VALID_JWT"}
		jwt := &oidc.ParsedJWT{Provider: oidc.DuoProviderName}

		jwtParser := verifmocks.NewParser(t)
		jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(jwt, nil)
		jwtParser.EXPECT().VerifyJwt(t.Context(), jwt).Return(errors.New("invalid jwt"))

		sut := issuerverif.NewService(jwtParser, nil)

		_, err := sut.Verify(t.Context(), nil, proof)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
		assert.ErrorContains(t, err, "invalid jwt")
	})

	t.Run("when issuer common name does not match JWT common name", func(t *testing.T) {
		t.Parallel()

		issuer := &issuertypes.Issuer{
			CommonName:   veriftesting.ValidProofIssuer,
			Organization: "Some Org",
		}
		jwt := &oidc.ParsedJWT{
			Provider: oidc.DuoProviderName,
			Claims: &oidc.Claims{
				Issuer:  "http://" + veriftesting.ValidProofIssuer,
				Subject: "test",
			},
			CommonName: "INVALID ISSUER",
		}

		jwtParser := verifmocks.NewParser(t)
		jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(jwt, nil)
		jwtParser.EXPECT().VerifyJwt(t.Context(), jwt).Return(nil)

		sut := issuerverif.NewService(jwtParser, nil)

		_, err := sut.Verify(t.Context(), issuer, &vctypes.Proof{Type: "JWT"})

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_ISSUER)
		assert.ErrorContains(t, err, "common name does not match issuer")
	})
}

//nolint:funlen // subtests
func TestVerifyExistingIssuer_Should_Fail(t *testing.T) {
	t.Parallel()

	t.Run("when proof is nil", func(t *testing.T) {
		t.Parallel()

		sut := issuerverif.NewService(nil, nil)

		_, err := sut.VerifyExistingIssuer(t.Context(), nil)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
		assert.ErrorContains(t, err, "proof is empty")
	})

	t.Run("when proof is not jwt", func(t *testing.T) {
		t.Parallel()

		invalidProof := &vctypes.Proof{Type: "INVALID_TYPE"}
		sut := issuerverif.NewService(nil, nil)

		_, err := sut.VerifyExistingIssuer(t.Context(), invalidProof)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_UNSUPPORTED_PROOF)
	})

	t.Run("when jwt fails to parse", func(t *testing.T) {
		t.Parallel()

		proof := &vctypes.Proof{Type: "JWT", ProofValue: "INVALID_JWT"}

		jwtParser := verifmocks.NewParser(t)
		jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(nil, errors.New("invalid jwt"))

		sut := issuerverif.NewService(jwtParser, nil)

		_, err := sut.VerifyExistingIssuer(t.Context(), proof)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
		assert.ErrorContains(t, err, "invalid jwt")
	})

	t.Run("when issuer does not exist", func(t *testing.T) {
		t.Parallel()

		proof := &vctypes.Proof{Type: "JWT", ProofValue: "VALID_JWT"}
		jwt := &oidc.ParsedJWT{Provider: oidc.DuoProviderName}

		jwtParser := verifmocks.NewParser(t)
		jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(jwt, nil)

		issuerRepo := issuermocks.NewRepository(t)
		issuerRepo.EXPECT().GetIssuer(t.Context(), mock.Anything).Return(nil, errcore.ErrResourceNotFound)

		sut := issuerverif.NewService(jwtParser, issuerRepo)

		_, err := sut.VerifyExistingIssuer(t.Context(), proof)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_ISSUER_NOT_REGISTERED)
	})

	t.Run("when jwt verification fails", func(t *testing.T) {
		t.Parallel()

		proof := &vctypes.Proof{Type: "JWT", ProofValue: "VALID_JWT"}
		jwt := &oidc.ParsedJWT{Provider: oidc.DuoProviderName, CommonName: "ISSUER"}
		issuer := &issuertypes.Issuer{
			CommonName:   "ISSUER",
			Organization: "Some Org",
		}

		jwtParser := verifmocks.NewParser(t)
		jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(jwt, nil)
		jwtParser.EXPECT().VerifyJwt(t.Context(), jwt).Return(errors.New("invalid jwt"))

		issuerRepo := issuermocks.NewRepository(t)
		issuerRepo.EXPECT().GetIssuer(t.Context(), jwt.CommonName).Return(issuer, nil)

		sut := issuerverif.NewService(jwtParser, issuerRepo)

		_, err := sut.VerifyExistingIssuer(t.Context(), proof)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
		assert.ErrorContains(t, err, "invalid jwt")
	})

	t.Run("when the JWT is self issued and the issuer is IdP based", func(t *testing.T) {
		t.Parallel()

		proof := &vctypes.Proof{Type: "JWT", ProofValue: "VALID_JWT"}
		jwt := &oidc.ParsedJWT{
			Provider:   oidc.SelfProviderName,
			CommonName: "ISSUER",
			Claims:     &oidc.Claims{},
		}
		issuer := &issuertypes.Issuer{
			CommonName:   "ISSUER",
			Organization: "Some Org",
			AuthType:     issuertypes.ISSUER_AUTH_TYPE_IDP,
		}

		jwtParser := verifmocks.NewParser(t)
		jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(jwt, nil)
		jwtParser.EXPECT().VerifyJwt(t.Context(), jwt).Return(nil)

		issuerRepo := issuermocks.NewRepository(t)
		issuerRepo.EXPECT().GetIssuer(t.Context(), jwt.CommonName).Return(issuer, nil)

		sut := issuerverif.NewService(jwtParser, issuerRepo)

		_, err := sut.VerifyExistingIssuer(t.Context(), proof)

		errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_IDP_REQUIRED)
	})
}

func TestVerifyExistingIssuer_Should_Succeed(t *testing.T) {
	t.Parallel()

	proof := &vctypes.Proof{Type: "JWT", ProofValue: "VALID_JWT"}
	jwt := &oidc.ParsedJWT{
		Provider:   oidc.DuoProviderName,
		CommonName: "ISSUER",
		Claims:     &oidc.Claims{},
	}
	issuer := &issuertypes.Issuer{
		CommonName:   "ISSUER",
		Organization: "Some Org",
		AuthType:     issuertypes.ISSUER_AUTH_TYPE_IDP,
	}

	jwtParser := verifmocks.NewParser(t)
	jwtParser.EXPECT().ParseJwt(t.Context(), mock.Anything).Return(jwt, nil)
	jwtParser.EXPECT().VerifyJwt(t.Context(), jwt).Return(nil)

	issuerRepo := issuermocks.NewRepository(t)
	issuerRepo.EXPECT().GetIssuer(t.Context(), jwt.CommonName).Return(issuer, nil)

	sut := issuerverif.NewService(jwtParser, issuerRepo)

	result, err := sut.VerifyExistingIssuer(t.Context(), proof)

	assert.NoError(t, err)
	assert.Equal(t, issuer, result.Issuer)
}
