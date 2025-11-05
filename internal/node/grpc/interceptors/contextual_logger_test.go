// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package interceptors_test

import (
	"context"
	"testing"

	"github.com/agntcy/identity/internal/node/grpc/interceptors"
	"github.com/agntcy/identity/internal/pkg/log"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestContextualLoggerUnary_should_enrich_with_grpc_request(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctx = metadata.NewIncomingContext(
		ctx,
		metadata.New(
			map[string]string{
				"key1": "key1_value",
				"key2": "key2_value",
			},
		),
	)
	fullMethod := uuid.NewString()

	handlerWithAssertion := func(ctx context.Context, req any) (any, error) {
		reqField := log.FromContext(ctx).Data["request"]
		fullMethodField := log.FromContext(ctx).Data["full_method"]

		assert.Equal(
			t,
			logrus.Fields{"key1": "key1_value", "key2": "key2_value"},
			reqField,
		)
		assert.Equal(t, fullMethod, fullMethodField)

		return "", nil
	}

	_, _ = interceptors.ContextualLoggerUnary(
		ctx,
		nil,
		&grpc.UnaryServerInfo{FullMethod: fullMethod},
		handlerWithAssertion,
	)
}
