// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package interceptors_test

import (
	"context"
	"net/http"
	"net/textproto"
	"testing"

	"github.com/agntcy/identity/internal/node/grpc/interceptors"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type mockStream struct {
	mock.Mock
}

func (*mockStream) Method() string {
	return ""
}
func (m *mockStream) SetHeader(md metadata.MD) error {
	args := m.Called(md)
	return args.Error(0)
}

func (m *mockStream) SendHeader(md metadata.MD) error {
	args := m.Called(md)
	return args.Error(0)
}

func (*mockStream) SetTrailer(_ metadata.MD) error {
	return nil
}

func TestRequestIDUnary(t *testing.T) {
	t.Parallel()

	t.Run("should set request ID header in gRPC stream with new value", func(t *testing.T) {
		t.Parallel()

		stream := &mockStream{}
		stream.On("SetHeader", mock.Anything).
			Return(nil).
			Run(func(args mock.Arguments) {
				md, _ := args.Get(0).(metadata.MD)
				vals := md.Get(interceptors.RequestIDHeader)

				assert.Len(t, vals, 1)
				assert.NotEmpty(t, vals[0])
			})

		ctx := grpc.NewContextWithServerTransportStream(context.Background(), stream)

		_, _ = interceptors.RequestIdUnary(
			ctx,
			"req",
			&grpc.UnaryServerInfo{},
			func(ctx context.Context, req any) (any, error) {
				return "res", nil
			},
		)
	})

	t.Run("should re-use the request ID passed with the gRPC request", func(t *testing.T) {
		t.Parallel()

		expectedRequestID := uuid.NewString()
		ctxWithMD := metadata.NewIncomingContext(t.Context(), map[string][]string{
			interceptors.RequestIDHeader: {expectedRequestID},
		})

		stream := &mockStream{}
		stream.On("SetHeader", mock.Anything).
			Return(nil).
			Run(func(args mock.Arguments) {
				md, _ := args.Get(0).(metadata.MD)
				vals := md.Get(interceptors.RequestIDHeader)

				assert.Len(t, vals, 1)
				assert.Equal(t, expectedRequestID, vals[0])
			})

		ctx := grpc.NewContextWithServerTransportStream(ctxWithMD, stream)

		_, _ = interceptors.RequestIdUnary(
			ctx,
			"req",
			&grpc.UnaryServerInfo{},
			func(ctx context.Context, req any) (any, error) {
				return "res", nil
			},
		)
	})
}

type mockResponseWriter struct {
	mock.Mock
}

func (m *mockResponseWriter) Header() http.Header {
	args := m.Called()
	err, _ := args.Get(0).(http.Header)

	return err
}

func (*mockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (*mockResponseWriter) WriteHeader(_ int) {}

func TestRequestIdHttpForwardResponseOption(t *testing.T) {
	t.Parallel()

	requestID := uuid.NewString()
	md := metadata.Pairs(interceptors.RequestIDHeader, requestID)
	ctx := runtime.NewServerMetadataContext(
		context.Background(),
		runtime.ServerMetadata{HeaderMD: md},
	)

	t.Run("should fetch request ID from gRPC context and set an HTTP header", func(t *testing.T) {
		t.Parallel()

		header := make(http.Header)

		w := &mockResponseWriter{}
		w.On("Header").Return(header)

		_ = interceptors.RequestIdHttpForwardResponseOption(ctx, w, nil)

		assert.Contains(t, header, interceptors.RequestIDHeader)
		assert.Equal(t, requestID, header[interceptors.RequestIDHeader][0])
	})

	t.Run("should return gRPC request ID header from HTTP header map", func(t *testing.T) {
		t.Parallel()

		grpcHeader := runtime.MetadataHeaderPrefix + textproto.CanonicalMIMEHeaderKey(interceptors.RequestIDHeader)
		header := http.Header{
			grpcHeader: []string{requestID},
		}

		w := &mockResponseWriter{}
		w.On("Header").Return(header)

		_ = interceptors.RequestIdHttpForwardResponseOption(ctx, w, nil)

		assert.NotContains(t, header, grpcHeader)
	})
}
