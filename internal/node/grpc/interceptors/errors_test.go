// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package interceptors_test

import (
	"context"
	"errors"
	"testing"

	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	"github.com/agntcy/identity/internal/node/grpc/interceptors"
	"github.com/agntcy/identity/internal/pkg/errutil"
	"github.com/agntcy/identity/internal/pkg/grpcutil"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestErrorInterceptor(t *testing.T) {
	t.Parallel()

	testCases := map[string]*struct {
		err         error
		isProd      bool
		expectedErr error
	}{
		"should return no errors": {
			err:         nil,
			expectedErr: nil,
		},
		"should return the gRPC error received from the next handler": {
			err:         grpcutil.BadRequestError(errors.New("failed")),
			expectedErr: grpcutil.BadRequestError(errors.New("failed")),
		},
		"should return internal gRPC error with the original msg for errtypes.ERROR_REASON_INTERNAL": {
			err:         errutil.ErrInfo(errtypes.ERROR_REASON_INTERNAL, "oops", errors.New("failed")),
			expectedErr: grpcutil.InternalError(errors.New("oops: failed")),
		},
		"should return internal gRPC error with the original msg for errtypes.ERROR_REASON_UNSPECIFIED": {
			err:         errutil.ErrInfo(errtypes.ERROR_REASON_UNSPECIFIED, "oops", errors.New("failed")),
			expectedErr: grpcutil.InternalError(errors.New("oops: failed")),
		},
		"should return internal gRPC error with the original msg for non custom error": {
			err:         errors.New("failed"),
			expectedErr: grpcutil.InternalError(errors.New("failed")),
		},
		"should return internal gRPC error with a custom msg in prod for errtypes.ERROR_REASON_INTERNAL": {
			isProd:      true,
			err:         errutil.ErrInfo(errtypes.ERROR_REASON_INTERNAL, "oops", errors.New("failed")),
			expectedErr: grpcutil.InternalError(interceptors.ErrInternalError),
		},
		"should return internal gRPC error with a custom msg in prod for errtypes.ERROR_REASON_UNSPECIFIED": {
			isProd:      true,
			err:         errutil.ErrInfo(errtypes.ERROR_REASON_UNSPECIFIED, "oops", errors.New("failed")),
			expectedErr: grpcutil.InternalError(interceptors.ErrInternalError),
		},
		"should return internal gRPC error with a custom msg in prod for non custom error": {
			isProd:      true,
			err:         errors.New("failed"),
			expectedErr: grpcutil.InternalError(interceptors.ErrInternalError),
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			t.Parallel()

			sut := interceptors.NewErrorInterceptor(tc.isProd)

			_, err := sut.Unary(
				t.Context(),
				"request",
				&grpc.UnaryServerInfo{},
				func(ctx context.Context, req any) (any, error) {
					return "response", tc.err
				},
			)

			assert.ErrorIs(t, err, tc.expectedErr)
		})
	}
}
