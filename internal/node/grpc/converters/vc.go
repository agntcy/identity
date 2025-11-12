// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package converters

import (
	coreapi "github.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/pkg/convertutil"
	"github.com/agntcy/identity/internal/pkg/log"
	"github.com/agntcy/identity/internal/pkg/ptrutil"
	"google.golang.org/protobuf/types/known/structpb"
)

func ToEnvelopedCredential(src *coreapi.EnvelopedCredential) *vctypes.EnvelopedCredential {
	if src == nil {
		return nil
	}

	return &vctypes.EnvelopedCredential{
		EnvelopeType: vctypes.CredentialEnvelopeType(
			ptrutil.Derefrence(src.EnvelopeType, 0),
		),
		Value: ptrutil.DerefStr(src.Value),
	}
}

func FromCredentialSchema(src *vctypes.CredentialSchema) *coreapi.CredentialSchema {
	if src == nil {
		return nil
	}

	return &coreapi.CredentialSchema{
		Type: &src.Type,
		Id:   &src.ID,
	}
}

func FromProof(src *vctypes.Proof) *coreapi.Proof {
	if src == nil {
		return nil
	}

	return &coreapi.Proof{
		Type:         &src.Type,
		ProofPurpose: &src.ProofPurpose,
		ProofValue:   &src.ProofValue,
	}
}

func ToProof(src *coreapi.Proof) *vctypes.Proof {
	if src == nil {
		return nil
	}

	return &vctypes.Proof{
		Type:         ptrutil.DerefStr(src.Type),
		ProofPurpose: ptrutil.DerefStr(src.ProofPurpose),
		ProofValue:   ptrutil.DerefStr(src.ProofValue),
	}
}

func FromVerifiableCredential(src *vctypes.VerifiableCredential) *coreapi.VerifiableCredential {
	if src == nil {
		return nil
	}

	content, err := structpb.NewValue(src.CredentialSubject)
	if err != nil {
		log.Warn(err)
	}

	return &coreapi.VerifiableCredential{
		Context:        src.Context,
		Type:           src.Type,
		Issuer:         &src.Issuer,
		Content:        content.GetStructValue(),
		Id:             &src.ID,
		IssuanceDate:   &src.IssuanceDate,
		ExpirationDate: &src.ExpirationDate,
		CredentialSchema: convertutil.ConvertSlice(
			src.CredentialSchema,
			FromCredentialSchema,
		),
		CredentialStatus: convertutil.ConvertSlice(src.Status, FromCredentialStatus),
		Proof:            FromProof(src.Proof),
	}
}

func FromVerificationResult(src *vctypes.VerificationResult) *coreapi.VerificationResult {
	if src == nil {
		return nil
	}

	return &coreapi.VerificationResult{
		Status:                       &src.Status,
		Document:                     FromVerifiableCredential(src.Document),
		MediaType:                    &src.MediaType,
		Controller:                   &src.Controller,
		ControlledIdentifierDocument: &src.ControlledIdentifierDocument,
		Warnings: convertutil.ConvertSlice(src.Warnings, func(err errtypes.ErrorInfo) *coreapi.ErrorInfo {
			return FromErrorInfo(&err)
		}),
		Errors: convertutil.ConvertSlice(src.Errors, func(err errtypes.ErrorInfo) *coreapi.ErrorInfo {
			return FromErrorInfo(&err)
		}),
	}
}

func FromCredentialStatus(src *vctypes.CredentialStatus) *coreapi.CredentialStatus {
	if src == nil {
		return nil
	}

	return &coreapi.CredentialStatus{
		Id:      &src.ID,
		Type:    &src.Type,
		Purpose: ptrutil.Ptr(coreapi.CredentialStatusPurpose(src.Purpose)),
	}
}
