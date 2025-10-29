// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"

	issuercoretypes "github.com/agntcy/identity/internal/core/issuer/types"
	"github.com/agntcy/identity/internal/issuer/issuer/types"
	idptypes "github.com/agntcy/identity/internal/issuer/types"
	"github.com/agntcy/identity/internal/issuer/vault"
	"github.com/agntcy/identity/pkg/oidc"
	"github.com/google/uuid"
)

type authInput struct {
	vaultID   string
	keyID     string
	clientID  string
	idpConfig *idptypes.IdpConfig
}

type AuthOption func(in *authInput)

func WithIdpIssuing(idpConfig *idptypes.IdpConfig) AuthOption {
	return func(in *authInput) {
		in.idpConfig = idpConfig
	}
}

func WithSelfIssuing(vaultID, keyID, clientID string) AuthOption {
	return func(in *authInput) {
		in.vaultID = vaultID
		in.keyID = keyID
		in.clientID = clientID
	}
}

type Client interface {
	// Authentices will generate a JWT token based on the issuer auth type
	// (self issuing or IdP issuing)
	Authenticate(
		ctx context.Context,
		issuer *types.Issuer,
		options ...AuthOption,
	) (string, error)

	// Token generates a JWT token for the issuer using an IdP.
	Token(ctx context.Context, idpConfig *idptypes.IdpConfig) (string, error)

	// SelfIssuedToken generates a JWT token using the issuer's private key.
	// If clientID is provided, it will be used as the subject of the JWT.
	// Otherwise, one will be generated.
	SelfIssuedToken(
		ctx context.Context,
		issuer *types.Issuer,
		vaultID, keyID string,
		clientID string,
	) (string, error)
}

type client struct {
	auth     oidc.Authenticator
	vaultSrv vault.VaultService
}

func NewClient(
	auth oidc.Authenticator,
	vaultSrv vault.VaultService,
) Client {
	return &client{
		auth:     auth,
		vaultSrv: vaultSrv,
	}
}

func (s *client) Authenticate(
	ctx context.Context,
	issuer *types.Issuer,
	options ...AuthOption,
) (string, error) {
	var in authInput

	var token string

	var err error

	for _, opt := range options {
		opt(&in)
	}

	switch issuer.AuthType {
	case issuercoretypes.ISSUER_AUTH_TYPE_IDP:
		token, err = s.Token(ctx, in.idpConfig)
	case issuercoretypes.ISSUER_AUTH_TYPE_SELF:
		token, err = s.SelfIssuedToken(ctx, issuer, in.vaultID, in.keyID, in.clientID)
	default:
		err = errors.New("unknown authentication type")
	}

	return token, err
}

func (s *client) SelfIssuedToken(
	ctx context.Context,
	issuer *types.Issuer,
	vaultID, keyID string,
	clientID string,
) (string, error) {
	prvKey, err := s.vaultSrv.RetrievePrivKey(ctx, vaultID, keyID)
	if err != nil {
		return "", fmt.Errorf("error retrieving public key: %w", err)
	}

	sub := clientID
	if sub == "" {
		sub = uuid.NewString()
	}

	return oidc.SelfIssueJWT(
		issuer.CommonName,
		sub,
		prvKey,
	)
}

func (s *client) Token(ctx context.Context, idpConfig *idptypes.IdpConfig) (string, error) {
	return s.auth.Token(
		ctx,
		idpConfig.IssuerUrl,
		idpConfig.ClientId,
		idpConfig.ClientSecret,
	)
}
