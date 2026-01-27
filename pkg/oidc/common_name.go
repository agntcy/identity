// Copyright 2026 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type customCommonNameParser func(issuerURL *url.URL) (string, error)

var customParsers = map[string]customCommonNameParser{
	"login.microsoftonline.com": handleMicrosoftEntraAndPingIssuer,
	"auth.pingone.":             handleMicrosoftEntraAndPingIssuer,
}

func ParseCommonName(issuerURL string) (string, error) {
	if issuerURL == "" {
		return "", errors.New("issuer URL cannot be empty")
	}

	parsedUrl, err := url.Parse(issuerURL)
	if err != nil {
		return "", err
	}

	hostname := parsedUrl.Hostname()

	for k, customParser := range customParsers {
		if strings.HasPrefix(hostname, k) {
			return customParser(parsedUrl)
		}
	}

	return hostname, nil
}

func handleMicrosoftEntraAndPingIssuer(issuerURL *url.URL) (string, error) {
	if issuerURL == nil {
		return "", errors.New("issuerURL cannot be nil")
	}

	paths := splitURLPath(issuerURL.Path)
	if paths == nil {
		return issuerURL.Hostname(), nil
	}

	return fmt.Sprintf("%s.%s", paths[0], issuerURL.Hostname()), nil
}

func splitURLPath(path string) []string {
	return strings.Split(strings.TrimLeft(path, "/"), "/")
}
