// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package vc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	vc "github.com/agntcy/identity/pkg/vc/verify"

	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	idtypes "github.com/agntcy/identity/internal/core/id/types"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/pkg/nodeapi"
)

//nolint:gosec // Mock data for testing
const (
	mockIdentityNodeURL = "http://mock-identity-node"
	validCredentialID   = "OKTA-0oap59p4mjDM48Uev5d7"
	//nolint:lll // Mock data is long, but it's for testing purposes only
	validJWTCredential = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjM2ODY4YTU1LWE3ZWMtNDRiMy1iNGJiLTUzMjFiOWUyZWQ1OCJ9.eyJjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy9leGFtcGxlcy92MiJdLCJ0eXBlIjpbIk1DUFNlcnZlckJhZGdlIl0sImlzc3VlciI6ImRldi05MzE1Nzc3NS5va3RhLmNvbSIsImNyZWRlbnRpYVN1YmplY3QiOnsiYmFkZ2UiOiJ7XCJuYW1lXCI6XCJNeSBNQ1AgU2VydmVyXCIsXCJ1cmxcIjpcImh0dHA6Ly9sb2NhbGhvc3Q6OTA5MFwiLFwidG9vbHNcIjpbe1wibmFtZVwiOlwiZ2V0X2V4Y2hhbmdlX3JhdGVcIixcImRlc2NyaXB0aW9uXCI6XCJVc2UgdGhpcyB0byBnZXQgY3VycmVudCBleGNoYW5nZSByYXRlLlxcblxcbiAgICBBcmdzOlxcbiAgICAgICAgY3VycmVuY3lfZnJvbTogVGhlIGN1cnJlbmN5IHRvIGNvbnZlcnQgZnJvbSAoZS5nLiwgXFxcIlVTRFxcXCIpLlxcbiAgICAgICAgY3VycmVuY3lfdG86IFRoZSBjdXJyZW5jeSB0byBjb252ZXJ0IHRvIChlLmcuLCBcXFwiRVVSXFxcIikuXFxuICAgICAgICBjdXJyZW5jeV9kYXRlOiBUaGUgZGF0ZSBmb3IgdGhlIGV4Y2hhbmdlIHJhdGUgb3IgXFxcImxhdGVzdFxcXCIuIERlZmF1bHRzIHRvIFxcXCJsYXRlc3RcXFwiLlxcblxcbiAgICBSZXR1cm5zOlxcbiAgICAgICAgQSBkaWN0aW9uYXJ5IGNvbnRhaW5pbmcgdGhlIGV4Y2hhbmdlIHJhdGUgZGF0YSwgb3IgYW4gZXJyb3IgbWVzc2FnZSBpZiB0aGUgcmVxdWVzdCBmYWlscy5cXG4gICAgXCIsXCJwYXJhbWV0ZXJzXCI6XCJ7XFxcInByb3BlcnRpZXNcXFwiOntcXFwiY3VycmVuY3lfZGF0ZVxcXCI6e1xcXCJkZWZhdWx0XFxcIjpcXFwibGF0ZXN0XFxcIixcXFwidGl0bGVcXFwiOlxcXCJDdXJyZW5jeSBEYXRlXFxcIixcXFwidHlwZVxcXCI6XFxcInN0cmluZ1xcXCJ9LFxcXCJjdXJyZW5jeV9mcm9tXFxcIjp7XFxcImRlZmF1bHRcXFwiOlxcXCJVU0RcXFwiLFxcXCJ0aXRsZVxcXCI6XFxcIkN1cnJlbmN5IEZyb21cXFwiLFxcXCJ0eXBlXFxcIjpcXFwic3RyaW5nXFxcIn0sXFxcImN1cnJlbmN5X3RvXFxcIjp7XFxcImRlZmF1bHRcXFwiOlxcXCJFVVJcXFwiLFxcXCJ0aXRsZVxcXCI6XFxcIkN1cnJlbmN5IFRvXFxcIixcXFwidHlwZVxcXCI6XFxcInN0cmluZ1xcXCJ9fSxcXFwidHlwZVxcXCI6XFxcIm9iamVjdFxcXCJ9XCJ9XX0iLCJpZCI6Ik9LVEEtMG9hcDU5cDRtakRNNDhVZXY1ZDcifSwiaWQiOiI0OGNlNjlmZS1kOWI5LTQ3YzktYTUyNy0wNjZiZjViYTYzMTUiLCJpc3N1YW5jZURhdGUiOiIyMDI1LTA2LTEyVDA4OjAyOjQ0WiJ9.NpWfkbmvOC4eWqBDXd-_AkpcvPZEoVQxU9ib6jmK_qnjae86KyvXoguvRIfyKbcW2__JCR3kZb6iXSl-Ics44xnzv0ies6wE5H-I7sXCC8H_iPq34hBZwNlm6DmjMTbowJXBoKXl5I-Xej1xiHXzytwy2Fz05vgaObLIosgdqKYMvGnvle8dZwo4_CPVuA4RcJtUSDSip0pJNCXmx7SeYoDAMn_qO9ZMr22GbSk6EczWJnA74xjUtCrSQ7i5vB7mRewXRlsdK5YAesXsirbwYrH9Z08LudmGB8YhBlFf8oxkQLmPO0WpNlhgN7027mVNheSAEKRHSWHaWHnAH6549Q"
)

// Test helper functions

func createMockVerifier() vc.Verifier {
	return vc.NewVerifier(NewMockNodeClientProvider())
}

func createCredential(value string, envelopeType vctypes.CredentialEnvelopeType) *vctypes.EnvelopedCredential {
	return &vctypes.EnvelopedCredential{
		Value:        value,
		EnvelopeType: envelopeType,
	}
}

func createCredentialJSON(value string, envelopeType vctypes.CredentialEnvelopeType) string {
	return `{"value": "` + value + `", "envelopeType": "` + envelopeType.String() + `"}`
}

func assertError(t *testing.T, err error, expectedReason errtypes.ErrorReason, description string) {
	t.Helper()
	assert.NotNil(t, err, "Expected an error for "+description)
	assert.IsType(t, errtypes.ErrorInfo{}, err, "Expected error to be of type ErrorInfo")
	assert.Equal(t, expectedReason, func() errtypes.ErrorInfo {
		var target errtypes.ErrorInfo
		_ = errors.As(err, &target)
		return target
	}().Reason, "Expected error reason to match for "+description)
}

func assertValidCredential(t *testing.T, result *vctypes.VerifiableCredential, err error) {
	t.Helper()
	assert.Nil(t, err, "Expected no error for valid credential")
	assert.NotNil(t, result, "Expected result to be not nil for valid credential")
	assert.IsType(t, &vctypes.VerifiableCredential{}, result, "Expected result to be of type VerifiableCredential")
	assert.Equal(t, "dev-93157775.okta.com", result.Issuer, "Expected issuer ID to match")
	assert.Equal(t, validCredentialID, result.CredentialSubject["id"], "Expected credential subject ID to match")
	assert.Equal(t, "MCPServerBadge", result.Type[0], "Expected credential type to match")
	assert.Equal(t, "2025-06-12T08:02:44Z", result.IssuanceDate, "Expected issuance date to match")
	assert.IsType(t, "string", result.CredentialSubject["badge"], "Expected badge to be a string in credential subject")
}

// Mock implementations

type mockClientProvider struct{}

func NewMockNodeClientProvider() nodeapi.ClientProvider {
	return &mockClientProvider{}
}

func (mockClientProvider) New(host string) (nodeapi.NodeClient, error) {
	return NewMockNodeClient(host)
}

type mockNodeClient struct{}

func NewMockNodeClient(host string) (nodeapi.NodeClient, error) {
	return &mockNodeClient{}, nil
}

func (c *mockNodeClient) RegisterIssuer(ctx context.Context, issuer *issuertypes.Issuer, proof *vctypes.Proof) error {
	return nil
}

//nolint:nilnil // Mock implementation for GenerateID
func (c *mockNodeClient) GenerateID(
	ctx context.Context,
	issuer *issuertypes.Issuer,
	proof *vctypes.Proof,
) (*idtypes.ResolverMetadata, error) {
	return nil, nil
}

func (c *mockNodeClient) PublishVerifiableCredential(ec *vctypes.EnvelopedCredential, proof *vctypes.Proof) error {
	return nil
}

//nolint:lll // Long data for testing purposes
func (c *mockNodeClient) ResolveMetadataByID(ctx context.Context, id string) (*idtypes.ResolverMetadata, error) {
	if id == validCredentialID {
		return &idtypes.ResolverMetadata{
			ID: id,
			VerificationMethod: []*idtypes.VerificationMethod{{
				ID: id,
				PublicKeyJwk: &idtypes.Jwk{
					ALG: "RS256",
					KTY: "RSA",
					USE: "sig",
					KID: "36868a55-a7ec-44b3-b4bb-5321b9e2ed58",
					E:   "AQAB",
					N:   "x5PNZpAhio4qEj20tADVA7irly-oDddW0F-7EBQc4S45tXrrtUp5g80sOFGjAPHv2rlWCO-bd_CBZcI1IOhRs8CqOFsWAzaDTi8jerR2a8Zmlm-sotUgdbJYZnCr4QDEkQmJtMPgri7ruSFa6okXK5c3F4LQEkr000ph6kh8-gRGl-veEOMLX5c6Y_5_CmNHB43Y5HpctyeyGf_VITwN6TLMiWjKWvl1fyGcz8BJedtharJiVt3HMAiyConOvp9ezgEeNf6Wuzj1dM6B-y0I9R2XyF5dnwq2yVc9OE_STbU2rVeHluCnqqYbJdqOLJT16EP_mpTlxdKR6xEhsNnoIw",
				},
			}},
			Service:         nil,
			AssertionMethod: nil,
		}, nil
	}

	return nil, errtypes.ErrorInfo{
		Reason:  errtypes.ERROR_REASON_RESOLVER_METADATA_NOT_FOUND,
		Message: "Resolver Metadata not found for ID: " + id,
		Err:     nil,
	}
}

// Test cases

func TestVerifier(t *testing.T) {
	t.Parallel()

	t.Run("NewVerifier", func(t *testing.T) {
		t.Parallel()
		verifier := createMockVerifier()
		assert.NotNil(t, verifier, "Verifier should not be nil")
	})
}

func TestVerifierCredential(t *testing.T) {
	t.Parallel()
	t.Run("VerifyCredential", func(t *testing.T) {
		t.Parallel()
		verifier := createMockVerifier()

		testCases := []struct {
			name          string
			credential    *vctypes.EnvelopedCredential
			expectedError errtypes.ErrorReason
			shouldSucceed bool
		}{
			{
				name:          "NilCredential",
				credential:    nil,
				expectedError: errtypes.ERROR_REASON_UNSPECIFIED,
			},
			{
				name:          "BadCredentialValue",
				credential:    createCredential("bad-credential", vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE),
				expectedError: errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			},
			{
				name:          "UnspecifiedEnvelopeType",
				credential:    createCredential("mock-credential", vctypes.CREDENTIAL_ENVELOPE_TYPE_UNSPECIFIED),
				expectedError: errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE,
			},
			{
				name:          "UnsupportedEnvelopeType",
				credential:    createCredential("mock-credential", vctypes.CREDENTIAL_ENVELOPE_TYPE_EMBEDDED_PROOF),
				expectedError: errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE,
			},
			{
				name:          "ValidCredential",
				credential:    createCredential(validJWTCredential, vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE),
				shouldSucceed: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				result, err := verifier.VerifyCredential(context.Background(), tc.credential, mockIdentityNodeURL)

				if tc.shouldSucceed {
					assertValidCredential(t, result, err)
				} else {
					assertError(t, err, tc.expectedError, tc.name)
					assert.Nil(t, result, "Expected result to be nil for "+tc.name)
				}
			})
		}
	})
}

func TestVerifierBadge(t *testing.T) {
	t.Parallel()
	t.Run("VerifyBadge", func(t *testing.T) {
		t.Parallel()
		verifier := createMockVerifier()

		testCases := []struct {
			name          string
			badgeJSON     string
			expectedError errtypes.ErrorReason
			shouldSucceed bool
		}{
			{
				name:          "EmptyBadge",
				badgeJSON:     "",
				expectedError: errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			},
			{
				name:          "BadBadgeValue",
				badgeJSON:     createCredentialJSON("bad-credential", vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE),
				expectedError: errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			},
			{
				name:          "UnspecifiedEnvelopeType",
				badgeJSON:     createCredentialJSON("mock-credential", vctypes.CREDENTIAL_ENVELOPE_TYPE_UNSPECIFIED),
				expectedError: errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE,
			},
			{
				name:          "UnsupportedEnvelopeType",
				badgeJSON:     createCredentialJSON("mock-credential", vctypes.CREDENTIAL_ENVELOPE_TYPE_EMBEDDED_PROOF),
				expectedError: errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE,
			},
			{
				name:          "ValidCredential",
				badgeJSON:     createCredentialJSON(validJWTCredential, vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE),
				shouldSucceed: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				result, err := verifier.VerifyBadge(context.Background(), tc.badgeJSON, mockIdentityNodeURL)

				if tc.shouldSucceed {
					assertValidCredential(t, result, err)
				} else {
					assertError(t, err, tc.expectedError, tc.name)
					assert.Nil(t, result, "Expected result to be nil for "+tc.name)
				}
			})
		}
	})
}
