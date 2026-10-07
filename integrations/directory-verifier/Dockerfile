# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /verifier ./cmd/verifier
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /verifier /verifier
EXPOSE 8443
ENTRYPOINT ["/verifier"]
