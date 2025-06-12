// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"context"
	"encoding/json"

	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	idtypes "github.com/agntcy/identity/internal/core/id/types"
	"github.com/agntcy/identity/internal/core/vc/jose"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/pkg/errutil"
	"github.com/agntcy/identity/internal/pkg/nodeapi"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Verifier defines the interface for verifying verifiable credentials (badges)
type Verifier interface {
	VerifyCredential(
		ctx context.Context,
		credential *vctypes.EnvelopedCredential,
		identityNodeURL string,
	) (*vctypes.VerifiableCredential, error)
}

// Verifier implementation that uses a NodeClientProvider to resolve metadata
type verifier struct {
	nodeClientPrv nodeapi.ClientProvider
}

// NewVerifier creates a new Verifier instance with the provided NodeClientProvider
func NewVerifier(
	nodeClientPrv nodeapi.ClientProvider,
) Verifier {
	return &verifier{
		nodeClientPrv: nodeClientPrv,
	}
}

// VerifyCredential verifies a verifiable credential (badge) using the Resolver Metadata public key
// from the identity node, and returns the parsed VerifiableCredential.
func (v *verifier) VerifyCredential(
	ctx context.Context,
	credential *vctypes.EnvelopedCredential,
	identityNodeURL string,
) (*vctypes.VerifiableCredential, error) {
	// Create a new NodeClient using the provided identityNodeURL
	client, err := v.nodeClientPrv.New(identityNodeURL)
	if err != nil || client == nil {
		return nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_UNSPECIFIED,
			"Failed to create NodeClient for identity node: "+identityNodeURL,
			err,
		)
	}

	// Ensure the credential is not nil
	if credential == nil {
		return nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_UNSPECIFIED,
			"credential is nil",
			nil,
		)
	}

	// Based on the EnvelopeType, handle the verification process
	// Note: Currently, only JOSE envelope type is supported for badge verification
	switch credential.EnvelopeType {
	case vctypes.CREDENTIAL_ENVELOPE_TYPE_EMBEDDED_PROOF:
		// Embedded proof badges are not supported for verification yet
		return nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE,
			"embedded proof badges are not supported for verification",
			nil,
		)

	case vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE:
		// Decode the JWT from the credential value
		jwt, err := jws.Parse([]byte(credential.Value))
		if err != nil {
			return nil, errutil.ErrInfo(
				errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
				"error parsing JWT from credential value",
				err,
			)
		}

		// Load the payload from the JWT
		var validatedVC vctypes.VerifiableCredential

		err = json.Unmarshal(jwt.Payload(), &validatedVC)
		if err != nil {
			return nil, errutil.ErrInfo(
				errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
				"error unmarshaling JWT payload to VerifiableCredential",
				err,
			)
		}

		// Load the claims from the CredentialSubject
		claims := &vctypes.BadgeClaims{}

		err = claims.FromMap(validatedVC.CredentialSubject)
		if err != nil {
			return nil, errutil.ErrInfo(
				errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
				"error loading claims from CredentialSubject",
				err,
			)
		}

		// Resolve the Resolver Metadata ID to get the public key
		resolvedMetadata, err := client.ResolveMetadataByID(ctx, claims.ID)
		if err != nil {
			return nil, errutil.ErrInfo(
				errtypes.ERROR_REASON_RESOLVER_METADATA_NOT_FOUND,
				"error resolving metadata by ID",
				err,
			)
		}

		// Convert resolvedMetadata.VerificationMethods to JWKs
		var jwks idtypes.Jwks
		for _, vm := range resolvedMetadata.VerificationMethod {
			jwks.Keys = append(jwks.Keys, vm.PublicKeyJwk)
		}

		// Verify the badge using the Resolver Metadata public key
		parsedVC, err := jose.Verify(&jwks, credential)
		if err != nil {
			return nil, errutil.ErrInfo(
				errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
				"error verifying badge with Resolver Metadata public key",
				err,
			)
		}

		// Return the parsed VerifiableCredential
		return parsedVC, nil

	default:
		// If the envelope type is not supported, return an error
		return nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE,
			"unsupported credential envelope type",
			nil,
		)
	}
}

// VerifyBadge verifies a badge JSON string and returns the parsed VerifiableCredential
func (v *verifier) VerifyBadge(
	ctx context.Context,
	badgeJson string,
	identityNodeURL string,
) (*vctypes.VerifiableCredential, error) {
	// Unmarshal the badge JSON into an EnvelopedCredential
	var badge *vctypes.EnvelopedCredential

	err := json.Unmarshal([]byte(badgeJson), &badge)
	if err != nil {
		return nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			"error unmarshaling badge JSON to EnvelopedCredential",
			err,
		)
	}

	// Call the VerifyCredential method with the provided badge
	return v.VerifyCredential(ctx, badge, identityNodeURL)
}
