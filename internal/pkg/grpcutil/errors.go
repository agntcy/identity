// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpcutil

import (
	"errors"

	coreapi "github.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	"github.com/agntcy/identity/internal/pkg/ptrutil"
	"github.com/agntcy/identity/pkg/log"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NotFoundError(err error) error {
	return newStatusWithDetails(codes.NotFound, err)
}

func UnauthorizedError(err error) error {
	return newStatusWithDetails(codes.Unauthenticated, err)
}

func UnimplementedError(err error) error {
	return newStatusWithDetails(codes.Unimplemented, err)
}

func BadRequestError(err error) error {
	return newStatusWithDetails(codes.InvalidArgument, err)
}

func InternalError(err error) error {
	return newStatusWithDetails(codes.Internal, err)
}

func newStatusWithDetails(c codes.Code, err error) error {
	st := status.New(c, err.Error())

	var errInfo errtypes.ErrorInfo

	if errors.As(err, &errInfo) {
		st, _ = st.WithDetails(&coreapi.ErrorInfo{
			Reason: ptrutil.Ptr(coreapi.ErrorReason(errInfo.Reason)),
		})

		switch errInfo.Reason {
		case errtypes.ERROR_REASON_UNSPECIFIED, errtypes.ERROR_REASON_INTERNAL:
			log.WithFields(logrus.Fields{log.ErrorField: err}).Error(err.Error())
		default:
			log.WithFields(logrus.Fields{log.ErrorField: err}).Warn(err.Error())
		}
	}

	return st.Err()
}
