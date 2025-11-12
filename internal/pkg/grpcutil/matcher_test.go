// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpcutil_test

import (
	"testing"

	"github.com/agntcy/identity/internal/pkg/grpcutil"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/assert"
)

func TestMatcher_CustomMatcher(t *testing.T) {
	t.Parallel()

	testCases := map[string]*struct {
		inHeader       string
		expectedHeader string
		expectedOk     bool
	}{
		"should match permanent HTTP header": {
			inHeader:       "Authorization",
			expectedHeader: runtime.MetadataPrefix + "Authorization",
			expectedOk:     true,
		},
		"should match x-request-id HTTP header": {
			inHeader:       "X-Request-Id",
			expectedHeader: "X-Request-Id",
			expectedOk:     true,
		},
		"should not match random HTTP header": {
			inHeader:       uuid.NewString(),
			expectedHeader: "",
			expectedOk:     false,
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			t.Parallel()

			actualHeader, actualOk := grpcutil.CustomMatcher(tc.inHeader)

			assert.Equal(t, tc.expectedHeader, actualHeader)
			assert.Equal(t, tc.expectedOk, actualOk)
		})
	}
}
