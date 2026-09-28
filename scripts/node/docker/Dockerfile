# Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.26.8-alpine3.23@sha256:a8fa79c5bd40d880b52bd3b6d7669ecdcfd00e85facdd427d279efb5ddd79cb1 AS builder

ARG BIN="/usr/local/bin"
ARG BUF_VERSION="1.28.1"

WORKDIR /identity

COPY ./scripts/node/docker/entrypoint.sh .
COPY ./scripts/node/docker/templates ./templates

RUN apk update && apk --no-cache add curl

RUN curl -sSL \
    "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-$(uname -s)-$(uname -m)" \
    -o "${BIN}/buf" && \
    chmod +x "${BIN}/buf"

RUN go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.30.0 && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2 && \
    go install github.com/go-swagger/go-swagger/cmd/swagger@v0.36.6

WORKDIR /identity

RUN addgroup -S generator && adduser -u 1999 -S -G generator generator

RUN chmod +x entrypoint.sh && \
    chown -R generator:generator .

USER generator

ENTRYPOINT ["./entrypoint.sh"]
