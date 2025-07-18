// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package converters

import (
	coreapi "github.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/pkg/convertutil"
	"github.com/agntcy/identity/internal/pkg/ptrutil"
	"github.com/agntcy/identity/pkg/log"
	"google.golang.org/protobuf/types/known/structpb"
)

func FromEnvelopedCredential(src *vctypes.EnvelopedCredential) *coreapi.EnvelopedCredential {
	if src == nil {
		return nil
	}

	return &coreapi.EnvelopedCredential{
		EnvelopeType: ptrutil.Ptr(coreapi.CredentialEnvelopeType(src.EnvelopeType)),
		Value:        ptrutil.Ptr(src.Value),
	}
}

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

func FromCredentialContent(src *vctypes.CredentialContent) *coreapi.CredentialContent {
	if src == nil {
		return nil
	}

	content, err := structpb.NewValue(src.Content)
	if err != nil {
		log.Warn(err)
	}

	return &coreapi.CredentialContent{
		ContentType: ptrutil.Ptr(coreapi.CredentialContentType(src.Type)),
		Content:     content.GetStructValue(),
	}
}

func ToCredentialContent(src *coreapi.CredentialContent) *vctypes.CredentialContent {
	if src == nil {
		return nil
	}

	return &vctypes.CredentialContent{
		Type: vctypes.CredentialContentType(
			ptrutil.Derefrence(src.ContentType, 0),
		),
		Content: src.Content.AsMap(),
	}
}

func FromCredentialSchema(src *vctypes.CredentialSchema) *coreapi.CredentialSchema {
	if src == nil {
		return nil
	}

	return &coreapi.CredentialSchema{
		Type: ptrutil.Ptr(src.Type),
		Id:   ptrutil.Ptr(src.ID),
	}
}

func ToCredentialSchema(src *coreapi.CredentialSchema) *vctypes.CredentialSchema {
	if src == nil {
		return nil
	}

	return &vctypes.CredentialSchema{
		Type: ptrutil.DerefStr(src.Type),
		ID:   ptrutil.DerefStr(src.Id),
	}
}

func FromProof(src *vctypes.Proof) *coreapi.Proof {
	if src == nil {
		return nil
	}

	return &coreapi.Proof{
		Type:         ptrutil.Ptr(src.Type),
		ProofPurpose: ptrutil.Ptr(src.ProofPurpose),
		ProofValue:   ptrutil.Ptr(src.ProofValue),
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
		Issuer:         ptrutil.Ptr(src.Issuer),
		Content:        content.GetStructValue(),
		Id:             ptrutil.Ptr(src.ID),
		IssuanceDate:   ptrutil.Ptr(src.IssuanceDate),
		ExpirationDate: ptrutil.Ptr(src.ExpirationDate),
		CredentialSchema: convertutil.ConvertSlice(
			src.CredentialSchema,
			FromCredentialSchema,
		),
		CredentialStatus: convertutil.ConvertSlice(src.Status, FromCredentialStatus),
		Proof:            FromProof(src.Proof),
	}
}

func ToVerifiableCredential(src *coreapi.VerifiableCredential) *vctypes.VerifiableCredential {
	if src == nil {
		return nil
	}

	return &vctypes.VerifiableCredential{
		Context:           src.Context,
		Type:              src.Type,
		Issuer:            ptrutil.DerefStr(src.Issuer),
		CredentialSubject: src.Content.AsMap(),
		ID:                ptrutil.DerefStr(src.Id),
		IssuanceDate:      ptrutil.DerefStr(src.IssuanceDate),
		ExpirationDate:    ptrutil.DerefStr(src.ExpirationDate),
		CredentialSchema: convertutil.ConvertSlice(
			src.CredentialSchema,
			ToCredentialSchema,
		),
		Proof: ToProof(src.Proof),
	}
}

func FromVerificationResult(src *vctypes.VerificationResult) *coreapi.VerificationResult {
	if src == nil {
		return nil
	}

	return &coreapi.VerificationResult{
		Status:                       ptrutil.Ptr(src.Status),
		Document:                     FromVerifiableCredential(src.Document),
		MediaType:                    ptrutil.Ptr(src.MediaType),
		Controller:                   ptrutil.Ptr(src.Controller),
		ControlledIdentifierDocument: ptrutil.Ptr(src.ControlledIdentifierDocument),
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
		Id:      ptrutil.Ptr(src.ID),
		Type:    ptrutil.Ptr(src.Type),
		Purpose: ptrutil.Ptr(coreapi.CredentialStatusPurpose(src.Purpose)),
	}
}
