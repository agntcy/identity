// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	errcore "github.com/agntcy/identity/internal/core/errors"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	idcore "github.com/agntcy/identity/internal/core/id"
	idtypes "github.com/agntcy/identity/internal/core/id/types"
	issuerverification "github.com/agntcy/identity/internal/core/issuer/verification"
	vccore "github.com/agntcy/identity/internal/core/vc"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/pkg/errutil"
	"github.com/agntcy/identity/internal/pkg/log"
)

type VerifiableCredentialService interface {
	Publish(
		ctx context.Context,
		credential *vctypes.EnvelopedCredential,
		proof *vctypes.Proof,
	) error

	// Find the vcs by resolver metadata ID
	GetVcs(
		ctx context.Context,
		resolverMetadataID string,
	) ([]*vctypes.EnvelopedCredential, error)

	// Parse and verify a Verifiable Credential
	Verify(
		ctx context.Context,
		credential *vctypes.EnvelopedCredential,
	) (*vctypes.VerificationResult, error)

	// Revoke a Verifiable Credential. THIS ACTION IS NOT REVERSIBLE.
	Revoke(
		ctx context.Context,
		credential *vctypes.EnvelopedCredential,
		proof *vctypes.Proof,
	) error
}

type verifiableCredentialService struct {
	idRepository idcore.IdRepository
	verifService issuerverification.Service
	vcRepository vccore.Repository
}

func NewVerifiableCredentialService(
	idRepository idcore.IdRepository,
	verifService issuerverification.Service,
	vcRepository vccore.Repository,
) VerifiableCredentialService {
	return &verifiableCredentialService{
		idRepository: idRepository,
		verifService: verifService,
		vcRepository: vcRepository,
	}
}

func (s *verifiableCredentialService) Publish(
	ctx context.Context,
	credential *vctypes.EnvelopedCredential,
	proof *vctypes.Proof,
) error {
	parsedVC, _, err := s.verifyEnvelopedCredential(ctx, credential, false)
	if err != nil {
		return err
	}

	id, ok := parsedVC.GetDID()
	if !ok {
		return errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			"unable to find the ID inside the CredentialSubject",
			nil,
		)
	}

	log.FromContext(ctx).Debug("Validating the authentication proof")

	issuerVerification, err := s.verifService.VerifyExistingIssuer(ctx, proof)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(id, issuerVerification.Subject) {
		return errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			"the ID in the Verifiable Credential does not match the ID in the proof",
			nil,
		)
	}

	log.FromContext(ctx).Debug("Storing the Verifiable Credential")

	_, err = s.vcRepository.Create(ctx, parsedVC, id)
	if err != nil {
		return errutil.ErrInfo(
			errtypes.ERROR_REASON_INTERNAL,
			"unable to store verifiable credential",
			err,
		)
	}

	return nil
}

func (s *verifiableCredentialService) GetVcs(
	ctx context.Context,
	resolverMetadataID string,
) ([]*vctypes.EnvelopedCredential, error) {
	log.FromContext(ctx).Debug(
		"Retrieving well-known verifiable credentials for resolver metadata ID: ",
		resolverMetadataID,
	)

	vcs, err := s.vcRepository.GetByResolverMetadata(ctx, resolverMetadataID)
	if err != nil {
		if errors.Is(err, errcore.ErrResourceNotFound) {
			log.FromContext(ctx).Debug(
				"No well-known verifiable credentials found for resolver metadata ID ",
				resolverMetadataID,
			)

			return []*vctypes.EnvelopedCredential{}, nil
		}

		return nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_INTERNAL,
			"unable to retrieve well-known verifiable credentials",
			err,
		)
	}

	log.FromContext(ctx).Debug(
		"Found well-known verifiable credentials for resolver metadata ID ",
		resolverMetadataID,
	)

	var envelopedCredentials []*vctypes.EnvelopedCredential

	for _, cred := range vcs {
		if cred.Proof == nil {
			log.FromContext(ctx).Debug("Skipping credential with empty proof for ID: ", cred.ID)
			continue
		}

		if cred.Proof.Type == "" {
			log.FromContext(ctx).Debug("Skipping credential with empty proof type for ID: ", cred.ID)
			continue
		}

		if cred.Proof.ProofValue == "" {
			log.FromContext(ctx).Debug("Skipping credential with empty proof value for ID: ", cred.ID)
			continue
		}

		switch cred.Proof.Type {
		case "JWT":
			envelopedCredentials = append(envelopedCredentials, &vctypes.EnvelopedCredential{
				EnvelopeType: vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE,
				Value:        cred.Proof.ProofValue,
			})
		default:
			log.FromContext(ctx).Debug(
				"Skipping credential with unsupported proof type: ",
				cred.Proof.Type,
				" for ID: ",
				cred.ID,
			)
		}
	}

	return envelopedCredentials, nil
}

// Verify an existing Verifiable Credential
func (s *verifiableCredentialService) Verify(
	ctx context.Context,
	credential *vctypes.EnvelopedCredential,
) (*vctypes.VerificationResult, error) {
	vc, resolverMD, err := s.verifyEnvelopedCredential(ctx, credential, true)
	if err == nil {
		return &vctypes.VerificationResult{
			Status:                       true,
			Document:                     vc,
			Controller:                   resolverMD.Controller,
			ControlledIdentifierDocument: resolverMD.ID,
			MediaType:                    "application/vp",
		}, nil
	}

	var errInfo errtypes.ErrorInfo
	if !errors.As(err, &errInfo) {
		return nil, err
	}

	if errInfo.Reason == errtypes.ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED {
		return &vctypes.VerificationResult{
			Status:                       false,
			Document:                     vc,
			Controller:                   resolverMD.Controller,
			ControlledIdentifierDocument: resolverMD.ID,
			MediaType:                    "application/vp",
			Warnings:                     []errtypes.ErrorInfo{errInfo},
		}, nil
	}

	return &vctypes.VerificationResult{
		Status: false,
		Errors: []errtypes.ErrorInfo{errInfo},
	}, nil
}

func (s *verifiableCredentialService) verifyEnvelopedCredential(
	ctx context.Context,
	credential *vctypes.EnvelopedCredential,
	checkStatus bool,
) (*vctypes.VerifiableCredential, *idtypes.ResolverMetadata, error) {
	if credential.Value == "" {
		return nil, nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT,
			"invalid credential envelope value",
			nil,
		)
	}

	parsedVC, err := vccore.ParseEnvelopedCredential(credential)
	if err != nil {
		return nil, nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT,
			"invalid credential envelope value",
			err,
		)
	}

	id, ok := parsedVC.GetDID()
	if !ok {
		return nil, nil, errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			"unable to find the ID inside the CredentialSubject",
			nil,
		)
	}

	log.FromContext(ctx).Debug("Resolving the ID into a ResolverMetadata")

	resolverMD, err := s.idRepository.ResolveID(ctx, id)
	if err != nil {
		if errors.Is(err, errcore.ErrResourceNotFound) {
			return nil, nil, errutil.ErrInfo(
				errtypes.ERROR_REASON_RESOLVER_METADATA_NOT_FOUND,
				fmt.Sprintf("could not resolve the ID (%s) to a resolver metadata", id),
				err,
			)
		}

		return nil, nil, errutil.ErrInfo(errtypes.ERROR_REASON_INTERNAL, "unexpected error", err)
	}

	log.FromContext(ctx).Debug("Validating the verifiable credential")

	err = vccore.VerifyEnvelopedCredential(credential, resolverMD.GetJwks(), checkStatus)

	return parsedVC, resolverMD, err
}

func (s *verifiableCredentialService) Revoke(
	ctx context.Context,
	credential *vctypes.EnvelopedCredential,
	proof *vctypes.Proof,
) error {
	parsedVC, _, err := s.verifyEnvelopedCredential(ctx, credential, false)
	if err != nil {
		return err
	}

	id, ok := parsedVC.GetDID()
	if !ok {
		return errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			"unable to find the ID inside the CredentialSubject",
			nil,
		)
	}

	log.FromContext(ctx).Debug("Validating the authentication proof")

	issuerVerification, err := s.verifService.VerifyExistingIssuer(ctx, proof)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(id, issuerVerification.Subject) {
		return errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			"the ID in the Verifiable Credential does not match the ID in the proof",
			nil,
		)
	}

	if !slices.ContainsFunc(parsedVC.Status, func(status *vctypes.CredentialStatus) bool {
		return status.Purpose == vctypes.CREDENTIAL_STATUS_PURPOSE_REVOCATION
	}) {
		return errutil.ErrInfo(
			errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
			"unable to find the revocation status in credentialStatus",
			nil,
		)
	}

	storedVC, err := s.vcRepository.GetByID(ctx, parsedVC.ID)
	if err != nil {
		if errors.Is(err, errcore.ErrResourceNotFound) {
			return errutil.ErrInfo(
				errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL,
				fmt.Sprintf("unable to find the Verifiable Credential %s", parsedVC.ID),
				err,
			)
		}

		return errutil.ErrInfo(errtypes.ERROR_REASON_INTERNAL, "unexpected error", err)
	}

	for _, status := range storedVC.Status {
		if status.Purpose == vctypes.CREDENTIAL_STATUS_PURPOSE_REVOCATION {
			return errutil.ErrInfo(
				errtypes.ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED,
				"the Verifiable Credential is already revoked",
				nil,
			)
		}
	}

	log.FromContext(ctx).Debug("Storing the Verifiable Credential")

	_, err = s.vcRepository.Update(ctx, parsedVC, id)
	if err != nil {
		return errutil.ErrInfo(
			errtypes.ERROR_REASON_INTERNAL,
			"unable to store verifiable credential",
			err,
		)
	}

	return nil
}
