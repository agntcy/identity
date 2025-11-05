// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package interceptors

import (
	"context"
	"fmt"
	"net/http"
	"net/textproto"

	"github.com/agntcy/identity/internal/pkg/identitycontext"
	"github.com/agntcy/identity/internal/pkg/log"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	RequestIDHeader string = "X-Request-Id"
)

// RequestIdUnary injects a request ID in the gRPC context
func RequestIdUnary(
	ctx context.Context,
	req any,
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	requestID := uuid.NewString()
	ctxWithReqID := identitycontext.InsertRequestID(ctx, requestID)

	resp, err := handler(ctxWithReqID, req)

	setRequestIDHeader(ctxWithReqID, requestID)

	return resp, err
}

func setRequestIDHeader(ctx context.Context, requestID string) {
	header := metadata.Pairs(RequestIDHeader, requestID)

	err := grpc.SetHeader(ctx, header)
	if err != nil {
		log.WithError(err).Error("unable to set X-Request-ID header")
	}
}

// RequestIdHttpForwardResponseOption gets the request ID added in the gRPC context
// and injects it in the HTTP response
func RequestIdHttpForwardResponseOption(
	ctx context.Context,
	w http.ResponseWriter,
	_ proto.Message,
) error {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if !ok {
		return nil
	}

	if vals := md.HeaderMD.Get(RequestIDHeader); len(vals) > 0 {
		w.Header().Set(RequestIDHeader, vals[0])

		// delete the gRPC request id header from the http response
		delete(
			w.Header(),
			fmt.Sprintf(
				"%s%s",
				runtime.MetadataHeaderPrefix,
				textproto.CanonicalMIMEHeaderKey(RequestIDHeader),
			),
		)
	}

	return nil
}
