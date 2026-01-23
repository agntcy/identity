// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"

	"golang.org/x/oauth2/clientcredentials"
)

type Authenticator interface {
	Token(
		ctx context.Context,
		issuer string,
		clientID string,
		clientSecret string,
	) (string, error)

	TokenWithScopes(
		ctx context.Context,
		issuer string,
		clientID string,
		clientSecret string,
		scopes []string,
	) (string, error)
}

type oidcAuthenticator struct{}

func NewAuthenticator() Authenticator {
	return &oidcAuthenticator{}
}

func (oidcAuthenticator) Token(
	ctx context.Context,
	issuer string,
	clientID string,
	clientSecret string,
) (string, error) {
	provider, err := getProviderMetadata(ctx, issuer)
	if err != nil {
		return "", err
	}

	conf := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     provider.TokenURL,
		Scopes:       []string{},
	}

	token, err := conf.Token(ctx)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func (a *oidcAuthenticator) TokenWithScopes(
	ctx context.Context,
	issuer string,
	clientID string,
	clientSecret string,
	scopes []string,
) (string, error) {
	provider, err := getProviderMetadata(ctx, issuer)
	if err != nil {
		return "", err
	}

	conf := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     provider.TokenURL,
		Scopes:       scopes, // caller decides scopes
	}

	token, err := conf.Token(ctx)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
