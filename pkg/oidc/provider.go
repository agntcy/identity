// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/agntcy/identity/internal/pkg/httputil"
	"github.com/agntcy/identity/internal/pkg/log"
)

func (p *parser) detectProviderName(
	ctx context.Context,
	provider *providerMetadata,
) (ProviderName, error) {
	_, headers, err := httputil.Get(ctx, provider.JWKSURL, nil)
	if err != nil {
		return UnknownProviderName, err
	}

	providerUrl, _ := url.Parse(provider.JWKSURL)

	switch {
	case isOry(headers, providerUrl.Host):
		return OryProviderName, nil
	case isOkta(headers, providerUrl.Host):
		return OktaProviderName, nil
	case isDuo(headers, providerUrl.Host):
		return DuoProviderName, nil
	case isPing(headers, providerUrl.Host):
		return PingProviderName, nil
	default:
		return IdpProviderName, nil
	}
}

func isOry(headers http.Header, host string) bool {
	return headers != nil &&
		(headers.Get("Ory-Network-Region") != "" || strings.HasSuffix(host, "oryapis.com"))
}

func isOkta(headers http.Header, _ string) bool {
	return headers != nil && headers.Get("X-Okta-Request-Id") != ""
}

func isDuo(headers http.Header, host string) bool {
	return headers != nil &&
		(strings.HasPrefix(strings.ToLower(headers.Get("Server")), "duo") ||
			strings.HasPrefix(host, "duosecurity.com"))
}

func isPing(_ http.Header, host string) bool {
	return strings.HasSuffix(host, "pingone.com") ||
		strings.HasSuffix(host, "pingone.eu") ||
		strings.HasSuffix(host, "pingone.com.au") ||
		strings.HasSuffix(host, "pingone.ca")
}

func getProviderMetadata(ctx context.Context, issuer string) (*providerMetadata, error) {
	metadata, oidcErr := getOidcProviderMetadata(ctx, issuer)
	if oidcErr == nil {
		return metadata, nil
	}

	metadata, oauthErr := getOAuthProviderMetadata(ctx, issuer)
	if oauthErr == nil {
		return metadata, nil
	}

	return nil, errors.Join(oidcErr, oauthErr)
}

func getOidcProviderMetadata(ctx context.Context, issuer string) (*providerMetadata, error) {
	oidcWellKnownURL := getOidcWellKnownURL(issuer)
	log.Debug("Getting metadata from issuer:", issuer, " with URL:", oidcWellKnownURL)

	metadata, err := getAuthSrvMetadata(ctx, oidcWellKnownURL)
	if err != nil {
		return nil, err
	}

	return metadata, err
}

func getOAuthProviderMetadata(ctx context.Context, issuer string) (*providerMetadata, error) {
	oauthWellKnownURL := getOAuthWellKnownURL(issuer)

	metadata, err := getAuthSrvMetadata(ctx, oauthWellKnownURL)
	if err != nil {
		return nil, err
	}

	return metadata, err
}

func getAuthSrvMetadata(ctx context.Context, wellKnownURL string) (*providerMetadata, error) {
	var metadata providerMetadata

	log.Debug("Getting metadata for the autorization server:", wellKnownURL)

	err := httputil.GetJSON(ctx, wellKnownURL, &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata from issuer: %w", err)
	}

	log.Debug("Got metadata from issuer:", metadata)

	return &metadata, nil
}

func getOidcWellKnownURL(issuer string) string {
	return issuer + "/.well-known/openid-configuration"
}

func getOAuthWellKnownURL(issuer string) string {
	// Get host and path from the issuer URL
	u, err := url.Parse(issuer)
	if err != nil {
		log.Error("Failed to parse issuer URL:", err)
		return ""
	}

	// Construct the well-known URL for OAuth
	result, err := url.JoinPath(
		fmt.Sprintf("%s://%s", u.Scheme, u.Host),
		".well-known/oauth-authorization-server",
		u.Path,
	)
	if err != nil {
		log.Error("Failed to construct oauth well-know URL:", err)
		return ""
	}

	return result
}
