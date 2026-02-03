// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package node_test

import (
	"testing"

	errtesting "github.com/agntcy/identity/internal/core/errors/testing"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	"github.com/agntcy/identity/internal/core/issuer/verification"
	verifmocks "github.com/agntcy/identity/internal/core/issuer/verification/mocks"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/node"
	"github.com/agntcy/identity/pkg/oidc"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGenerateFromProof_Should_Generate_Correct_Prefixes(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider       oidc.ProviderName
		expectedPrefix string
	}{
		"Okta provider": {
			provider:       oidc.OktaProviderName,
			expectedPrefix: "OKTA-",
		},
		"Duo provider": {
			provider:       oidc.DuoProviderName,
			expectedPrefix: "DUO-",
		},
		"Ory provider": {
			provider:       oidc.OryProviderName,
			expectedPrefix: "ORY-",
		},
		"Generic IdP provider": {
			provider:       oidc.IdpProviderName,
			expectedPrefix: "IDP-",
		},
		"Ping provider": {
			provider:       oidc.PingProviderName,
			expectedPrefix: "PING-",
		},
		"Microsoft Entra provider": {
			provider:       oidc.EntraProviderName,
			expectedPrefix: "ENTRA-",
		},
		"Self provider": {
			provider:       oidc.SelfProviderName,
			expectedPrefix: "AGNTCY-",
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			t.Parallel()

			proof := &vctypes.Proof{Type: "JWT", ProofValue: "VALID_JWT"}
			issuer := &issuertypes.Issuer{
				CommonName:   "ISSUER",
				Organization: "Some Org",
				AuthType:     issuertypes.ISSUER_AUTH_TYPE_IDP,
			}
			subject := uuid.NewString()

			verifService := verifmocks.NewService(t)
			verifService.EXPECT().VerifyExistingIssuer(t.Context(), proof).Return(
				&verification.Result{
					Issuer:   issuer,
					Subject:  subject,
					Provider: tc.provider,
				}, nil)

			sut := node.NewIDGenerator(verifService)

			actualID, actualIssuer, err := sut.GenerateFromProof(t.Context(), proof)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedPrefix+subject, actualID)
			assert.Equal(t, issuer, actualIssuer)
		})
	}
}

func TestGenerateFromProof_Should_Fail_When_Provider_Is_Unknown(t *testing.T) {
	t.Parallel()

	proof := &vctypes.Proof{Type: "JWT", ProofValue: "VALID_JWT"}
	issuer := &issuertypes.Issuer{
		CommonName:   "ISSUER",
		Organization: "Some Org",
		AuthType:     issuertypes.ISSUER_AUTH_TYPE_IDP,
	}
	subject := uuid.NewString()

	verifService := verifmocks.NewService(t)
	verifService.EXPECT().VerifyExistingIssuer(t.Context(), proof).Return(
		&verification.Result{
			Issuer:  issuer,
			Subject: subject,
			// Unknow provider
		}, nil)

	sut := node.NewIDGenerator(verifService)

	_, _, err := sut.GenerateFromProof(t.Context(), proof)

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_UNKNOWN_IDP)
}
