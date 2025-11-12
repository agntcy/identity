// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package identitycontext

type contextKey string

const (
	RequestID contextKey = contextKey("request-id")
)
