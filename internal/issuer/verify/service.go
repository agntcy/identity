// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/agntcy/identity/internal/core/vc/jose"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/pkg/nodeapi"
	jwktype "github.com/agntcy/identity/pkg/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

type VerifyService interface {
	VerifyCredential(
		ctx context.Context,
		credential *vctypes.EnvelopedCredential,
		identityNodeURL string,
	) (*vctypes.VerifiableCredential, error)
}

type verifyService struct {
}

func NewVerifyService() VerifyService {
	return &verifyService{}
}

func (v *verifyService) VerifyCredential(
	ctx context.Context,
	credential *vctypes.EnvelopedCredential,
	identityNodeURL string,
) (*vctypes.VerifiableCredential, error) {
	nodeClientPrv := nodeapi.NewNodeClientProvider()

	client, err := nodeClientPrv.New(identityNodeURL)
	if err != nil {
		return nil, err
	}

	switch credential.EnvelopeType {
	case vctypes.CREDENTIAL_ENVELOPE_TYPE_EMBEDDED_PROOF:
		return nil, fmt.Errorf("badge verification is not supported for embedded proof badges yet")
	case vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE:
		// Decode the JWT
		raw, err := jws.Parse([]byte(credential.Value))
		if err != nil {
			return nil, fmt.Errorf("error parsing JWT: %w", err)
		}

		var validatedVC vctypes.VerifiableCredential

		err = json.Unmarshal(raw.Payload(), &validatedVC)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling JWT payload: %w", err)
		}

		claims := &vctypes.BadgeClaims{}

		err = claims.FromMap(validatedVC.CredentialSubject)
		if err != nil {
			return nil, err
		}

		// Resolve the Resolver Metadata ID to get the public key
		resolvedMetadata, err := client.ResolveMetadataByID(ctx, claims.ID)
		if err != nil {
			return nil, fmt.Errorf("error resolving Resolver Metadata ID: %w", err)
		}

		// convert resolvedMetadata.VerificationMethods to JWKs
		var jwks jwktype.Jwks
		for _, vm := range resolvedMetadata.VerificationMethod {
			jwks.Keys = append(jwks.Keys, vm.PublicKeyJwk)
		}

		// Verify the badge using the Resolver Metadata public key
		parsedVC, err := jose.VerifyAndParse(&jwks, credential)
		if err != nil {
			return nil, fmt.Errorf("error verifying badge: %w", err)
		}

		err = parsedVC.ValidateStatus()
		if err != nil {
			return nil, fmt.Errorf("error verifying badge status: %w", err)
		}

		return parsedVC, nil
	default:
		return nil, fmt.Errorf("unsupported badge envelope type: %s", credential.EnvelopeType)
	}
}
