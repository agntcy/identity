// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"

	nodeapi "github.com/agntcy/identity/api/server/agntcy/identity/node/v1alpha1"
	"github.com/agntcy/identity/internal/node"
	"github.com/agntcy/identity/internal/node/grpc/converters"
	"github.com/agntcy/identity/internal/pkg/grpcutil"
	"github.com/agntcy/identity/internal/pkg/log"
)

type issuerService struct {
	nodeIssuerService node.IssuerService
}

func NewIssuerService(nodeIssuerService node.IssuerService) nodeapi.IssuerServiceServer {
	return &issuerService{
		nodeIssuerService,
	}
}

// Register an issuer by providing the issuer details
func (i *issuerService) Register(
	ctx context.Context,
	req *nodeapi.RegisterIssuerRequest,
) (*nodeapi.RegisterIssuerResponse, error) {
	log.FromContext(ctx).Debug("RegisterIssuer: ", req.Issuer.CommonName)

	// Convert entities and call the node service
	err := i.nodeIssuerService.Register(
		ctx,
		converters.ToIssuer(req.Issuer),
		converters.ToProof(req.Proof),
	)
	if err != nil {
		return nil, grpcutil.Error(err)
	}

	// Return the action uri
	return &nodeapi.RegisterIssuerResponse{}, nil
}

// Returns the well-known document content for an issuer in
// Json Web Key Set (JWKS) format
func (i *issuerService) GetWellKnown(
	ctx context.Context,
	req *nodeapi.GetIssuerWellKnownRequest,
) (*nodeapi.GetIssuerWellKnownResponse, error) {
	log.FromContext(ctx).Debug("GetIssuerWellKnown: ", req.CommonName)

	// Get the issuer's public keys by common name
	jwks, err := i.nodeIssuerService.GetJwks(ctx, req.CommonName)
	if err != nil {
		return nil, grpcutil.Error(err)
	}

	return &nodeapi.GetIssuerWellKnownResponse{
		Jwks: converters.FromJwks(jwks),
	}, nil
}
