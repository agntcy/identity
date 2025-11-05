// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package interceptors

import (
	"context"
	"maps"

	"github.com/agntcy/identity/internal/pkg/log"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ContextualLoggerUnary Enriches the context with tenant and request metadata for structured logging.
//
// This interceptor extracts tenant related information (such as tenant ID, app ID, etc.) from
// the incoming context, as well as the full gRPC method name and the current request.
//
// Downstream handlers can then use log.FromContext(ctx) to access and include these enriched
// fields in their log entries.
func ContextualLoggerUnary(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	fields := make(logrus.Fields)

	fields["full_method"] = info.FullMethod

	requestFields := logrus.Fields{}

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		filtered := convertMetadataToMap(md)
		maps.Copy(requestFields, filtered)
	}

	if len(requestFields) > 0 {
		fields["request"] = requestFields
	}

	return handler(log.EnrichContext(ctx, fields), req)
}

func convertMetadataToMap(md metadata.MD) map[string]any {
	filtered := make(map[string]any)

	for k, v := range md {
		if len(v) == 0 {
			continue
		}

		filtered[k] = v[0]
	}

	return filtered
}
