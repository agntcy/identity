# Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
"""Main entry point for the Currency Agent server."""

import logging
import sys

import click
import httpx
import uvicorn
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import (
    BasePushNotificationSender,
    InMemoryPushNotificationConfigStore,
    InMemoryTaskStore,
)
from a2a.types import AgentCapabilities, AgentCard, AgentSkill
from dotenv import load_dotenv

from agent import CurrencyAgent
from agent_executor import CurrencyAgentExecutor

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.command()
@click.option("--host", "host", default="0.0.0.0")
@click.option("--port", "port", default=9091)
@click.option("--ollama-host", default="http://localhost:11434")
@click.option("--ollama-model", default="llama3.2")
@click.option("--mcp-server-url", default="http://localhost:9090/mcp")
def main(host, port, ollama_host, ollama_model, mcp_server_url):
    """Starts the Currency Agent server."""

    # pylint: disable=broad-exception-caught
    try:
        capabilities = AgentCapabilities(streaming=True, pushNotifications=True)
        skill = AgentSkill(
            id="convert_currency",
            name="Currency Exchange Rates Tool",
            description="Helps with exchange values between various currencies",
            tags=["currency conversion", "currency exchange"],
            examples=["What is exchange rate between USD and GBP?"],
        )
        agent_card = AgentCard(
            name="Currency Agent",
            description="Helps with exchange rates for currencies",
            url=f"http://{host}:{port}/",
            version="1.0.0",
            defaultInputModes=CurrencyAgent.SUPPORTED_CONTENT_TYPES,
            defaultOutputModes=CurrencyAgent.SUPPORTED_CONTENT_TYPES,
            capabilities=capabilities,
            skills=[skill],
        )

        # Initialize the HTTP client and request handler
        timeout = httpx.Timeout(connect=None, read=None, write=None, pool=None)
        httpx_client = httpx.AsyncClient(timeout=timeout)
        push_config_store = InMemoryPushNotificationConfigStore()
        request_handler = DefaultRequestHandler(
            agent_executor=CurrencyAgentExecutor(
                ollama_host, ollama_model, mcp_server_url
            ),
            task_store=InMemoryTaskStore(),
            push_config_store=push_config_store,
            push_sender=BasePushNotificationSender(httpx_client, push_config_store),
        )
        server = A2AStarletteApplication(
            agent_card=agent_card, http_handler=request_handler
        )

        uvicorn.run(server.build(), host=host, port=port)
    except Exception as e:
        logger.error("An error occurred during server startup: %e", e)
        sys.exit(1)


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    main()
