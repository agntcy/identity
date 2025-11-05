// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package identitycontext

import (
	"context"
)

// InsertRequestID inserts requestID into the context.
func InsertRequestID(ctx context.Context, requestID string) context.Context {
	if requestID != "" {
		return context.WithValue(ctx, RequestID, requestID)
	}

	return ctx
}

// GetRequestID fetches the request ID from a context (if any).
func GetRequestID(ctx context.Context) (string, bool) {
	requestID, ok := ctx.Value(RequestID).(string)

	return requestID, ok
}
