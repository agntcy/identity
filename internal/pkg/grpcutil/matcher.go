// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpcutil

import (
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

func CustomMatcher(key string) (string, bool) {
	return runtime.DefaultHeaderMatcher(key)
}
