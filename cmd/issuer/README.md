# Issuer CLI

The `Issuer CLI` tool provides identity management capabilities for the AGNTCY Internet of Agents.
It allows you to create and manage cryptographic keys, register as an issuer, generate metadata for identities, issue badges for Agent and MCP Server identities, and verify badges for existing identities.

## Prerequisites

To run or build the `CLI` locally, you need to have the following installed:

- [Golang](https://go.dev/doc/install) 1.24 or later

## Installation

To install the latest version of the `CLI`, you can use the following command:

```bash
go install github.com/agntcy/identity/cmd/issuer@latest && \
  ln -s $(go env GOPATH)/bin/issuer $(go env GOPATH)/bin/identity

```

## Usage

The `CLI` follows a hierarchical command structure:

```bash
identity [command] [subcommand] [flags]
```

### Core Commands

- **vault**: Manage cryptographic vaults and keys
- **issuer**: Register and manage issuer configurations
- **metadata**: Generate and manage metadata for identities
- **badge**: Issue and publish badges for identities
- **verify**: Verify identity badges
- **config**: Display the current configuration context

### Common Workflows

#### Step 1: Create a vault and generate cryptographic keys

```bash
# Configure a vault to store cryptographic keys
identity vault connect file -f ~/.identity/vault.json -v "My Vault"

# Generate a new key pair and store it in the vault
identity vault key generate
```

#### Step 2: Register as an issuer

Using an Identity Provider (IdP):

```bash
identity issuer register -o "My Organization" \
   -c "client-id" -s "client-secret" -u "https://idp.example.com"
```

Without an Identity Provider (IdP):

```bash
identity issuer register -o "My Organization" \
     -n "common-name"
```

> [!NOTE]
> This will create a new issuer configuration in the specified vault.
> Without an Identity Provider (IdP), the provided common name will not be verified
> and the issuer will be registered as a self-signed issuer.

#### Step 3: Generate metadata

Using an Identity Provider (IdP):

```bash
identity metadata generate \
    -c "client-id" -s "client-secret" -u "https://idp.example.com"
```

Without an Identity Provider (IdP):

```bash
identity metadata generate
```

#### Step 4: Issue a badge

```bash
identity badge issue [type] [options]
```

You can issue badges for different types content:

```bash
# OASF Files - https://schema.oasf.outshift.com/objects/record
identity badge issue oasf -f /path/to/oasf_content.json

# A2A Agent Cards - https://google.github.io/A2A/tutorials/python/3-agent-skills-and-card/#agent-card
identity badge issue a2a -u http://localhost:9091/.well-known/agent.json

# MCP Servers - (https://github.com/modelcontextprotocol/servers))
identity badge issue mcp -u http://localhost:9090
```

#### Step 5: Publish the badge

```bash
identity badge publish
```

### Managing Existing Components

**List existing vaults**:

```bash
identity vault list
```

**List existing keys**:

```bash
identity vault key list
```

**Show details of an issuer**:

```bash
identity issuer show -i [issuer-id]
```

**Load a different metadata configuration**:

```bash
identity metadata load -m [metadata-id]
```

**View current configuration**:

```bash
identity config
```

**Verify a list of badges from a file**:

```bash
identity verify -f /path/to/badges.json
```

## Documentation

For more detailed documentation on each command:

```bash
identity [command] --help
```

For a full command overview:

```bash
identity --help
```

## Development

### Building and running the Issuer CLI locally

To build the `CLI` from source:

```bash
go build -o identity cmd/issuer/main.go
```

Then move the binary to a location in your PATH (optional):

```bash
mv identity /usr/local/bin/
```

This will allow you to run the CLI from anywhere in your terminal with the command `identity`.

### Run without building

You can also run the CLI directly without building and installing it.
This is useful for testing or development purposes:

```bash
go run cmd/issuer/main.go
```
