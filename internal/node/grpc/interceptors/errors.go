// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package interceptors

import (
	"context"
	"errors"
	"fmt"

	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	"github.com/agntcy/identity/internal/pkg/grpcutil"
	"github.com/agntcy/identity/pkg/log"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var ErrInternalError = errors.New("internal server error")

type ErrorInterceptor struct {
	isProd bool
}

func NewErrorInterceptor(isProd bool) *ErrorInterceptor {
	return &ErrorInterceptor{isProd}
}

func (i ErrorInterceptor) Unary(
	ctx context.Context,
	req any,
	_ *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	resp, err := handler(ctx, req)
	if err != nil {
		// if it's a gRPC Status error then return it
		if _, ok := status.FromError(err); ok {
			log.WithFields(logrus.Fields{log.ErrorField: err}).Debug(err.Error())

			return resp, err
		}

		if errInfo := errtypes.AsErrorInfo(err); errInfo != nil {
			return resp, i.internalError(fmt.Errorf("%s: %w", errInfo.Message, errInfo.Err))
		}

		return resp, i.internalError(err)
	}

	return resp, err
}

func (i ErrorInterceptor) internalError(err error) error {
	log.Error(err)

	var finalErr error

	if i.isProd {
		finalErr = ErrInternalError
	} else {
		finalErr = err
	}

	return grpcutil.InternalError(finalErr)
}
