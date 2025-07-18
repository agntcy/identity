// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"fmt"

	coreapi "github.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1"
	nodeapi "github.com/agntcy/identity/api/server/agntcy/identity/node/v1alpha1"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	"github.com/agntcy/identity/internal/node"
	"github.com/agntcy/identity/internal/node/grpc/converters"
	"github.com/agntcy/identity/internal/pkg/grpcutil"
	"github.com/agntcy/identity/internal/pkg/ptrutil"
	"google.golang.org/protobuf/types/known/emptypb"
)

type vcService struct {
	vcSrv node.VerifiableCredentialService
}

func NewVcService(vcSrv node.VerifiableCredentialService) nodeapi.VcServiceServer {
	return &vcService{
		vcSrv: vcSrv,
	}
}

// Publish an issued Verifiable Credential
func (s *vcService) Publish(
	ctx context.Context,
	req *nodeapi.PublishRequest,
) (*emptypb.Empty, error) {
	err := s.vcSrv.Publish(
		ctx,
		converters.ToEnvelopedCredential(req.Vc),
		converters.ToProof(req.Proof),
	)
	if err != nil {
		if errtypes.IsErrorInfo(err, errtypes.ERROR_REASON_INTERNAL) {
			return nil, grpcutil.InternalError(err)
		}

		return nil, grpcutil.BadRequestError(err)
	}

	return &emptypb.Empty{}, nil
}

// Verify an existing Verifiable Credential
func (s *vcService) Verify(
	ctx context.Context,
	req *nodeapi.VerifyRequest,
) (*coreapi.VerificationResult, error) {
	result, err := s.vcSrv.Verify(ctx, converters.ToEnvelopedCredential(req.Vc))
	if err != nil {
		if errtypes.IsErrorInfo(err, errtypes.ERROR_REASON_INTERNAL) {
			return nil, grpcutil.InternalError(err)
		}

		return nil, grpcutil.BadRequestError(err)
	}

	return converters.FromVerificationResult(result), nil
}

// Returns the well-known Verifiable Credentials for the specified Id
func (s *vcService) GetWellKnown(
	ctx context.Context,
	req *nodeapi.GetVcWellKnownRequest,
) (*nodeapi.GetVcWellKnownResponse, error) {
	vcs, err := s.vcSrv.GetVcs(
		ctx,
		req.Id,
	)
	if err != nil {
		if errtypes.IsErrorInfo(err, errtypes.ERROR_REASON_INTERNAL) {
			return nil, grpcutil.InternalError(err)
		}

		return nil, grpcutil.BadRequestError(err)
	}

	response := &nodeapi.GetVcWellKnownResponse{
		Vcs: make([]*coreapi.EnvelopedCredential, 0, len(vcs)),
	}
	for _, vc := range vcs {
		response.Vcs = append(response.Vcs, &coreapi.EnvelopedCredential{
			EnvelopeType: ptrutil.Ptr(coreapi.CredentialEnvelopeType(vc.EnvelopeType)),
			Value:        &vc.Value,
		})
	}

	return response, nil
}

// Search for Verifiable Credentials based on the specified criteria
func (vcService) Search(
	ctx context.Context,
	req *nodeapi.SearchRequest,
) (*nodeapi.SearchResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

// Revoke an existing Verifiable Credential
func (s *vcService) Revoke(
	ctx context.Context,
	req *nodeapi.RevokeRequest,
) (*emptypb.Empty, error) {
	err := s.vcSrv.Revoke(
		ctx,
		converters.ToEnvelopedCredential(req.Vc),
		converters.ToProof(req.Proof),
	)
	if err != nil {
		if errtypes.IsErrorInfo(err, errtypes.ERROR_REASON_INTERNAL) {
			return nil, grpcutil.InternalError(err)
		}

		return nil, grpcutil.BadRequestError(err)
	}

	return &emptypb.Empty{}, nil
}
