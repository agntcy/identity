// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package grpcutil_test

import (
	"encoding/json"
	"errors"
	"testing"

	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	"github.com/agntcy/identity/internal/pkg/errutil"
	"github.com/agntcy/identity/internal/pkg/grpcutil"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/status"
)

func TestGrpcError(t *testing.T) {
	t.Parallel()

	generalErr := errors.New("some error")

	testCases := map[string]*struct {
		inErr  error
		outErr error
	}{
		"should return bad request status error for non errtypes.ERROR_REASON_INTERNAL": {
			inErr: errutil.ErrInfo(
				errtypes.ERROR_REASON_UNKNOWN_IDP,
				"some error",
				nil,
			),
			outErr: grpcutil.BadRequestError(errutil.ErrInfo(
				errtypes.ERROR_REASON_UNKNOWN_IDP,
				"some error",
				nil,
			)),
		},
		"should return the same error for errtypes.ERROR_REASON_INTERNAL": {
			inErr: errutil.ErrInfo(
				errtypes.ERROR_REASON_INTERNAL,
				"some error",
				nil,
			),
			outErr: errutil.ErrInfo(
				errtypes.ERROR_REASON_INTERNAL,
				"some error",
				nil,
			),
		},
		"should return the same error for errtypes.ERROR_REASON_UNSPECIFIED": {
			inErr: errutil.ErrInfo(
				errtypes.ERROR_REASON_UNSPECIFIED,
				"some error",
				nil,
			),
			outErr: errutil.ErrInfo(
				errtypes.ERROR_REASON_UNSPECIFIED,
				"some error",
				nil,
			),
		},
		"should return the same error as input when it is not ErrInfo": {
			inErr:  generalErr,
			outErr: generalErr,
		},
	}

	for tn, tc := range testCases {
		t.Run(tn, func(t *testing.T) {
			t.Parallel()

			actualErr := grpcutil.Error(tc.inErr)

			assert.ErrorIs(t, actualErr, tc.outErr)
		})
	}
}

func TestGrpcError_should_return_a_status_error_with_details(t *testing.T) {
	t.Parallel()

	inErr := errutil.ErrInfo(
		errtypes.ERROR_REASON_UNKNOWN_IDP,
		"some error",
		nil,
	)

	actualErr := grpcutil.Error(inErr)

	st, ok := status.FromError(actualErr)

	assert.True(t, ok)
	assert.Equal(t, inErr.Error(), st.Message())
	assert.Len(t, st.Details(), 1)

	detail := pbToMap(t, st.Details()[0])

	assert.Equal(
		t,
		map[string]any{
			"reason": float64(errtypes.ERROR_REASON_UNKNOWN_IDP),
		},
		detail,
	)
}

func pbToMap(t *testing.T, pb any) map[string]any {
	t.Helper()

	data, err := json.Marshal(&pb)
	assert.NoError(t, err)

	var m map[string]any

	assert.NoError(t, json.Unmarshal(data, &m))

	return m
}
