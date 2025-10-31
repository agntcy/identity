// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Appentifier: Apache-2.0

package grpctesting

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func AssertGrpcError(t *testing.T, err error, code codes.Code, msg string) {
	t.Helper()

	assert.Error(t, err)

	s, ok := status.FromError(err)
	assert.True(t, ok)

	assert.Equal(t, code, s.Code())
	assert.Equal(t, msg, s.Message())
}
