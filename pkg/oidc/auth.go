// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"

	"golang.org/x/oauth2/clientcredentials"
)

type AuthenticatorTokenOption func(config *clientcredentials.Config)

type Authenticator interface {
	Token(
		ctx context.Context,
		issuer string,
		clientID string,
		clientSecret string,
		options ...AuthenticatorTokenOption,
	) (string, error)
}

type oidcAuthenticator struct{}

func NewAuthenticator() Authenticator {
	return &oidcAuthenticator{}
}

func WithScopes(scopes []string) AuthenticatorTokenOption {
	return func(config *clientcredentials.Config) {
		config.Scopes = scopes
	}
}

func (oidcAuthenticator) Token(
	ctx context.Context,
	issuer string,
	clientID string,
	clientSecret string,
	options ...AuthenticatorTokenOption,
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

	for _, opt := range options {
		opt(&conf)
	}

	token, err := conf.Token(ctx)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
