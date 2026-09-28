# Agntcy Identity Node SDK for Go

[![OpenAPI v1alpha1](https://img.shields.io/badge/OpenAPI-v1alpha1-blue)](https://spec.identity.agntcy.org/openapi/node/v1alpha1)
[![Protocol Documentation](https://img.shields.io/badge/Protocol-Documentation-blue)](https://spec.identity.agntcy.org/protodocs/agntcy/identity/core/v1alpha1/id.proto)
[![Proto Spec](https://img.shields.io/badge/Proto-Spec-blue.svg)](https://github.com/agntcy/identity/tree/main/api/spec)

`github.com/agntcy/identity/api/client` is the v1alpha1 Agntcy Identity Node SDK for the Go programming language that contains the different REST HTTP clients.

The SDK requires a minimum version of `Go 1.26`.

## Getting started

To get started working with the SDK setup your GO projects and add the SDK dependencies with `go get`. The following example demonstrates how you can use the SDK to resolve an [ID](https://spec.identity.agntcy.org/docs/id/definitions) into a Resolver Metadata.

### Project Initialization

```sh
mkdir ~/id_example
cd ~/id_example
go mod init id_example
touch main.go
```

### Add SDK Dependency

```sh
go get github.com/agntcy/identity/api/client
```

### Code Example

```go
package main

import (
    "log"

    idsdk "github.com/agntcy/identity/api/client/client/id_service"
    apimodels "github.com/agntcy/identity/api/client/models"
    httptransport "github.com/go-openapi/runtime/client"
    "github.com/go-openapi/strfmt"
)

func main() {
    // Creating a new ID API client
    client := idsdk.New(httptransport.New("<NODE_HOST>", "", nil), strfmt.Default)

    // Resolving an ID into a Resolver Metadata
    res, err := client.ResolveID(&idsdk.ResolveIDParams{
        Body: &apimodels.V1alpha1ResolveRequest{
            ID: "<VALID_ID>",
        },
    })
    if err != nil {
        log.Fatalf("%v", err)
    }

    log.Printf("Status Code: %d", res.Code())
    log.Printf("Resolver Metadata: %v", res.Payload.ResolverMetadata)
}
```

### Run Code

```sh
go mod tidy
go run main.go
```

## For Maintainers

To generate the SDK, first make sure that Docker is running locally and then run the following command from the root of the repository:

```sh
make generate_node_sdk
```

The generation will be based on the spec located in `api/spec`.
