# Node Backend

The `Node Backend` is a core component of the Identity Platform, responsible for allowing organizations to register, issue and verify agent identities.
It provides a RESTful API for interaction with the Identity services.

## Prerequisites

To run the `Node Backend` locally, you need to have the following installed:

- [Docker](https://docs.docker.com/get-docker/)
- [Make](https://www.gnu.org/software/make/)

## Installation

## Starting the Node Backend with Docker

To start the `Node` locally with `Docker`, run the following command:

```bash
make start_node
```

To stop the `Node,` run:

```bash
make stop_node
```

> [!NOTE]
> This will deploy a local persistent `Postgres` database and a local `Node` backend.
> The `Postgres` database will be available at `0.0.0.0:5432`and the `Node` will be available at`0.0.0.0:4000`.

## Development

## Starting the Node Backend with Docker in Development Mode

To start the `Node` in development mode with `Docker`, run the following command:

```bash
make start_node dev=true
```

To stop the `Node,` run:

```bash
make stop_node
```

> [!NOTE]
> The `dev=true` flag is used to build the docker containers from the source code.
> This is useful for development purposes. If you want to use the pre-built images, you can omit this flag.
>
> This will deploy a local persistent `Postgres` database and a local `Node` backend.
> The `Postgres` database will be available at `0.0.0.0:5432`and the `Node` will be available at`0.0.0.0:4000`.

## Running the Node Backend locally

To run the `Node Backend` locally without Docker, you need to have the following installed:

- [Golang](https://go.dev/doc/install) 1.26 or later
- [Postgres](https://www.postgresql.org/download/) running locally or accessible via a connection string

The `Node Backend` uses a .env file to configure the connection to the Postgres database and other settings.
First, copy the `.env.example` file to `.env` and update the database values and any other settings as needed:

```bash
cp cmd/node/.env.example cmd/node/.env
```

Next, to run the `Node Backend` locally, navigate to the `cmd/node` directory and run the following command:

```bash
# From the root of the repository navigate to the cmd/node directory
cd cmd/node

# Run the Node backend using Go
go run .
```
