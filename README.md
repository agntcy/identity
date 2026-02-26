# Identity

[![Lint](https://github.com/agntcy/identity/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/marketplace/actions/super-linter)
[![Contributor-Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-fbab2c.svg)](CODE_OF_CONDUCT.md)

<p align="center">
  <a href="https://agntcy.org">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="img/_logo-Agntcy_White@2x.png" width="300">
      <img alt="" src="img/_logo-Agntcy_FullColor@2x.png" width="300">
    </picture>
  </a>
  <br />
  <caption>Welcome to the <b>Identity</b> repository</caption>
</p>

---

**AGNTCY Identity** provides a secure and verifiable method to uniquely identify agents through open and decentralized techniques. Each agent is assigned a universally unique identifier, backed by verifiable credentials (VCs).
**AGNTCY Identity** enables to bring your own identity using conventions like IDs assigned by Identity Providers (e.g., Okta) or Agent Cards (e.g., Google’s A2A), or be assigned an ID following standards (e.g., W3C DIDs).
This component ensures that every agent in the **AGNTCY** ecosystem has a verifiable, universally unique identity, enabling secure authentication, trusted communication, and interoperability across diverse multi-agent systems, regardless of the identity assignment method.

As the below diagram shows, the Agent's unique ID links both to metadata resolving that ID, and to one or more Agent Badges.  Agent Badges essentially are containers for verifying metadata. 

<p align="center">
   <picture>
   <source media="(prefers-color-scheme: dark)" srcset="img/agent-badge-dark.png" width="100%">
   <img alt="" src="img/agent-badge-light.png" width="100%">
   </picture>
</p>

- The ID links to a ResolverMetadata object for secure and automated verification.
- You can link to one or more Agent Badges. Why? Multiple badges can provide nuanced, task-specific access to different systems without over-privileging the agent. Agent Badges contain Verifiable Credentials (VCs), which include:
  - The Agent's ID
  - Schema definition (e.g., OASF)
  - Metadata for authentication and other security needs.

> [!NOTE]
> This same structure applies to MCP Servers and MASs, ensuring consistency across all identity-bearing entities in the Internet of Agents (IoA).

## 📚 Table of Contents

- 🚀 Architecting [Agentic Trust](#-architecting-agentic-trust)
- 🌟 [Features & Main Components](#-features--main-components)
- ⚡️ [Get Started](#%EF%B8%8F-get-started-in-5-minutes) in 5 Minutes
- 📜 See the core commands of the [CLI](#-core-commands-to-use-the-cli)
- 🧪 [Run the Demo](#-run-the-demo)

You can also:

- 📖 See the full [CLI](cmd/issuer/README.md) and [Node](cmd/node/README.md) docs
- 📦 Check-out the [Sample Agents and MCP servers](samples/README.md)
- 📘 Explore our full [Documentation](https://spec.identity.agntcy.org) to understand our platform's capabilities
- 📝 Dive into our [API Specs](https://spec.identity.agntcy.org/protodocs/agntcy/identity/core/v1alpha1/id.proto) for detailed API documentation

## 🚀 Architecting Agentic Trust

- **Core Principle**: Trust is foundational for the Internet of Agents.
- **Identity as the Root**: AGNTCY Identity ensures Agents and Tools (MCP Servers) are verifiably authentic.
- **Flexible & Interoperable**: BYOID (Bring Your Own ID), integrates with existing Identity Providers (IdPs) such as Okta.

Secure and reliable communication between software agents is a cornerstone of the Internet of Agents (IoA) vision.
Without proper identity management, malicious or unverified agents can infiltrate Multi-Agent Systems (MASs), leading to misinformation, fraud, or security breaches.
To mitigate these risks, the AGNTCY provides a standardized and consistent framework for authenticating agents and validating associated metadata.
This applies equally to:

- Agents
- Model Context Protocol (MCP) Servers
- MASs (Multi-Agent Systems)

> [!TIP]
> This repository includes an AI Agent and MCP Server to showcase the AGNTCY Identity components in action!

## 🌟 Features & Main Components

### Features

- **Identity creation**: Generate unique, verifiable identities for agents and MCP servers.
- **Existing identity onboarding**: Integrate identities from external IdPs.
- **Badge creation & verification**: Authenticate agents and MCP servers and validate metadata.

### Main Components

- **Issuer CLI**: Manage identities, vaults, and credentials.
- **Node Backend**: Backend server for identity management and metadata.

## ⚡️ Get Started in 5 Minutes

This short guide shows you how to set up the Identity `Issuer CLI` as well as the Identity `Node Backend`.
The `Issuer CLI` enables you to generate, register, search for, and verify badges for Agents and MCP Servers. It includes a library enabling storage and retrieval of the keys required to sign the badges, both on local storage or using a 3rd-party wallet or vault.
The `Node Backend` comprises the APIs and the backend core. It stores, maintains, and binds org:sub-org IDs, PubKeys, Subject IDs and metadata (including badges), ResolverMetadata, and Verifiable Credentials (VCs).

### Prerequisites

To run these steps, you must either:

- install [Docker Desktop](https://docs.docker.com/get-docker/), or
- have both [Docker Engine v27 or higher](https://docs.docker.com/engine/install/) and [Docker Compose v2.35 or higher](https://docs.docker.com/compose/install/)

### Step 1: Install the Issuer CLI

Use the following command to install the `Issuer CLI`:

using `curl`:

```bash
sh -c "$(curl -sSL https://raw.githubusercontent.com/agntcy/identity/refs/heads/main/deployments/scripts/identity/install_issuer.sh)"
```

or using `wget`:

```bash
sh -c "$(wget -qO- https://raw.githubusercontent.com/agntcy/identity/refs/heads/main/deployments/scripts/identity/install_issuer.sh)"
```

> [!NOTE]
> You can also download the `Issuer CLI` binary corresponding to your platform from the [latest releases](https://github.com/agntcy/identity/releases).
>
> On some platforms you might also need to add execution permissions and/or approve the binary in `System Security Settings`.
>
> For easier use, consider moving the binary to your `$PATH` or to the `/usr/local/bin` folder.

If you have `Golang` set up locally, you could also use the `go install command`:

```bash
go install github.com/agntcy/identity/cmd/issuer@latest && \
  ln -s $(go env GOPATH)/bin/issuer $(go env GOPATH)/bin/identity
```

### Step 2: Start the Node Backend with Docker

1. Clone the repository and navigate to the `identity` directory:

   ```bash
   git clone https://github.com/agntcy/identity.git && cd identity
   ```

2. Start the Node Backend with Docker:

   ```bash
   ./deployments/scripts/identity/launch_node.sh
   ```

   Or use `make` if available locally:

   ```bash
   make start_node
   ```

> [!NOTE]
> You can also install the `Node Backend` using our helm chart, for which instructions are available in the [chart's](charts/identity-node/README.md) directory.

### Step 3: Verify the Installation

You can verify the installation by running the command below to see the [different commands available](#-core-commands-to-use-the-cli):

```bash
identity -h
```

## 📜 Core commands to use the CLI

Here are the core commands you can use with the CLI

- **vault**: Manage cryptographic vaults and keys
- **issuer**: Register and manage issuer configurations
- **metadata**: Generate and manage metadata for identities
- **badge**: Issue and publish badges for identities
- **verify**: Verify identity badges
- **config**: Display the current configuration context

## 🧪 Run the demo

This scenario demonstrates how to use the AGNTCY Identity components in a real environment.
You will be able to:

- Register as an Issuer
- Generate metadata for an MCP Server
- Issue and publish a badge for the MCP Server
- Verify the published badge

### Prerequisites

First, follow the steps in the [Get Started in 5 minutes](#%EF%B8%8F-get-started-in-5-minutes) section above to install the `Issuer CLI` and run the `Node Backend`, and generate a local vault and keys.

To run this demo setup locally, you must:

- either install [Docker Desktop](https://docs.docker.com/get-docker/), or have both [Docker Engine v27 or higher](https://docs.docker.com/engine/install/) and [Docker Compose v2.35 or higher](https://docs.docker.com/compose/install/)
- [Ollama CLI](https://ollama.com/download)
- [Okta CLI](https://cli.okta.com/manual/#installation)

### Step 1: Run the Samples with Ollama and Docker

The agents in the samples rely on a local instance of the Llama 3.2 LLM to power the agent's capabilities.
With Ollama installed, you can download and run the model using the following command:

1. Run the Llama 3.2 model:

   ```bash
   ollama run llama3.2
   ```

> [!NOTE]
> The model is approximately 2GB.  Ensure you have enough disk space.

2. From the root of the repository, navigate to the `samples` directory and run the below command to deploy the `Currency Exchange A2A Agent` leveraging the `Currency Exchange MCP Server`:

   ```bash
   cd samples && docker compose up -d
   ```

3. [Optional] Test the samples using the provided [test clients](./samples/README.md#testing-the-samples).

### Step 2: Use the CLI to create a local Vault and generate keys

1. Create a local vault to store generated cryptographic keys:

   ```bash
   identity vault connect file -f ~/.identity/vault.json -v "My Vault"
   ```

2. Generate a new key pair and store it in the vault:

   ```bash
   identity vault key generate
   ```

### Step 3: Register as an Issuer

This demo uses Okta as an IdP to create an application for the Issuer.
To quickly create a trial account and application, we have provided a script to automate the process using the Okta CLI.

> [!IMPORTANT]
> If you already have an Okta account, you can use the `okta login` command to log in to your existing organization.
>
> If registering a new Okta developer account fails, proceed with manual trial signup and then use the `okta login` command,
> as instructed by the Okta CLI.

1. Run the following command from the root repository to create a new Okta application:

   ```bash
   . ./demo/scripts/create_okta_app
   ```

2. In the interactive prompt, choose the following options:

   `> 4: Service (Machine-to-Machine)`, `> 5: Other`

3. Register the Issuer using the `Issuer CLI` and the environment variables from the previous step:

   ```bash
   identity issuer register -o "My Organization" \
       -c "$OKTA_OAUTH2_CLIENT_ID" -s "$OKTA_OAUTH2_CLIENT_SECRET" -u "$OKTA_OAUTH2_ISSUER"
   ```

> [!NOTE]
> You can now access the `Issuer's Well-Known Public Key` at [`http://localhost:4000/v1alpha1/issuer/{common_name}/.well-known/jwks.json`](http://localhost:4000/v1alpha1/issuer/{common_name}/.well-known/jwks.json),
> where `{common_name}` is the common name you provided during registration.

### Step 4: Generate metadata for an MCP Server

Create a second application for the MCP Server metadata using Okta, similar to the previous step:

1. Run the following command from the root repository to create a new Okta application:

   ```bash
   . ./demo/scripts/create_okta_app
   ```

2. In the interactive prompt, choose the following options:

   `> 4: Service (Machine-to-Machine)`, `> 5: Other`

3. Generate metadata for the MCP Server using the `Issuer CLI` and the environment variables from the previous step:

   ```bash
   identity metadata generate -c "$OKTA_OAUTH2_CLIENT_ID" \
       -s "$OKTA_OAUTH2_CLIENT_SECRET" -u "$OKTA_OAUTH2_ISSUER"
   ```

> [!NOTE]
> This command prints the metadata ID, which you need in the next step to view published badges that are linked to this metadata.

### Step 5: Issue and Publish a Badge for the MCP Server

1. Issue a badge for the MCP Server:

   ```bash
   identity badge issue mcp -u http://localhost:9090 -n "My MCP Server"
   ```

2. Publish the badge:

   ```bash
   identity badge publish
   ```

> [!NOTE]
> You can now access the `VCs as a Well-Known` at [`http://localhost:4000/v1alpha1/vc/{metadata_id}/.well-known/vcs.json`](http://localhost:4000/v1alpha1/vc/{client_id}/.well-known/vcs.json),
> where `{metadata_id}` is the metadata ID you generated in the previous step.

### (Optional) Step 6: Verify a Published Badge

You can use the `Issuer CLI` to verify any published badge -- not just those you issued yourself.  
This also enables others to verify your published Agent and MCP badges in addition to their own.

1. Download the badge you created in Step 5 of the previous procedure, replacing {metadata_id} with the metadata ID from step 4:

   ```bash
   curl -o vcs.json http://localhost:4000/v1alpha1/vc/{metadata_id}/.well-known/vcs.json
   ```

2. Verify the badges using the `Issuer CLI`:

   ```bash
   identity verify -f vcs.json
   ```

> [!NOTE]
> You can also use [our Python SDK](sdk/python/README.md) to verify the badge programmatically.

## Development

For more detailed development instructions please refer to the following sections:

- [Node Backend](cmd/node/README.md)
- [Issuer CLI](cmd/issuer/README.md)
- [Samples](samples/README.md)
- [Api Spec](api/spec/README.md)
- [Node Client SDK](api/client/README.md)

## Roadmap

See the [open issues](https://github.com/agntcy/identity/issues) for a list
of proposed features (and known issues).

## Contributing

Contributions are what make the open source community such an amazing place to
learn, inspire, and create. Any contributions you make are **greatly
appreciated**. For detailed contributing guidelines, please see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Copyright Notice

[Copyright Notice and License](LICENSE)

Distributed under Apache 2.0 License. See LICENSE for more information.
Copyright [AGNTCY](https://github.com/agntcy) Contributors.
