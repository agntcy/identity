// Copyright 2026 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"fmt"
	"testing"

	"github.com/agntcy/identity/pkg/oidc"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestParseCommonName_Custom_Parsers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		issuer             string
		expectedCommonName string
	}{
		"should parse Ping .eu issuer and add tenant as a sub domain": {
			issuer:             "https://auth.pingone.eu/ced7cdd4-bd10-4745-9e70-c15bbfd5140e/as",
			expectedCommonName: "ced7cdd4-bd10-4745-9e70-c15bbfd5140e.auth.pingone.eu",
		},
		"should parse Ping .com issuer and add tenant as a sub domain": {
			issuer:             "https://auth.pingone.com/ced7cdd4-bd10-4745-9e70-c15bbfd5140e/as",
			expectedCommonName: "ced7cdd4-bd10-4745-9e70-c15bbfd5140e.auth.pingone.com",
		},
		"should parse Microsoft Entra issuer and add tenant as a sub domain": {
			issuer:             "https://login.microsoftonline.com/2562ec99-5676-453f-abad-42c297599ff4/v2.0",
			expectedCommonName: "2562ec99-5676-453f-abad-42c297599ff4.login.microsoftonline.com",
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			t.Parallel()

			actualCommonName, err := oidc.ParseCommonName(tc.issuer)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedCommonName, actualCommonName)
		})
	}
}

func TestParseCommonName_should_return_default_hostname(t *testing.T) {
	t.Parallel()

	hostname := fmt.Sprintf("%s.%s", uuid.NewString(), uuid.NewString())
	issuer := fmt.Sprintf("https://%s/%s/%s", hostname, uuid.NewString(), uuid.NewString())

	commonName, err := oidc.ParseCommonName(issuer)

	assert.NoError(t, err)
	assert.Equal(t, hostname, commonName)
}

func TestParseCommonName_should_return_err_for_empty_url(t *testing.T) {
	t.Parallel()

	emptyURL := ""

	_, err := oidc.ParseCommonName(emptyURL)

	assert.ErrorContains(t, err, "issuer URL cannot be empty")
}
