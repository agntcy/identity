// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpcutil

import (
	"slices"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

var customForwardedHTTPHeaders = []string{
	"X-Request-Id",
}

func CustomMatcher(key string) (string, bool) {
	h, ok := runtime.DefaultHeaderMatcher(key)
	if ok {
		return h, ok
	}

	if slices.Contains(customForwardedHTTPHeaders, key) {
		return key, true
	}

	return "", false
}
