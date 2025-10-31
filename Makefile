# Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

.PHONY: do_generate_proto do_generate_node_sdk do_generate_mocks do_start_node

do_generate_proto:
	cd scripts/proto && ./generate.sh
	@echo "Generated proto files"

do_generate_node_sdk:
	chmod +x scripts/node/generate.sh
	./scripts/node/generate.sh
	@echo "Generated Node SDK"

do_generate_mocks:
	cd scripts && ./mockery.sh
	@echo "Generated GO mocks with Mockery"

do_start_node:
	@./deployments/scripts/identity/launch_node.sh ${dev}
	@echo "Postgres started at :5984"
	@echo "Node started at :4000"

do_stop_node:
	@./deployments/scripts/identity/stop_node.sh
	@echo "Node stopped"
	@echo "Postgres stopped"

generate_proto: do_generate_proto

generate_node_sdk: do_generate_node_sdk

generate_mocks: do_generate_mocks

stop_node: do_stop_node
start_node: do_start_node
