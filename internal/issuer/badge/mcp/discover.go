// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	mcptypes "github.com/agntcy/identity/internal/issuer/badge/mcp/types"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

// The discoverClient interface defines the core methods for
// discovering a deployed MCP server
type DiscoveryClient interface {
	Discover(ctx context.Context, name, url string) (*mcptypes.McpServer, error)
}

// The discoverClient struct implements the DiscoverClient interface
type discoveryClient struct {
}

// NewDiscoverClient creates a new instance of the DiscoverClient
func NewDiscoveryClient() DiscoveryClient {
	return &discoveryClient{}
}

func (d *discoveryClient) Discover(
	ctx context.Context,
	name, url string,
) (*mcptypes.McpServer, error) {
	// Create streamable http client
	// We only support streamable http client for now
	mcpClient, err := client.NewStreamableHttpClient(fmt.Sprintf("%s/mcp", url))
	if err != nil {
		return nil, fmt.Errorf("failed to create mcp client: %w", err)
	}

	// Initialize the client
	_, err = mcpClient.Initialize(ctx, mcp.InitializeRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize mcp client: %w", err)
	}

	defer func(mcpClient *client.Client) {
		_ = mcpClient.Close()
	}(mcpClient)

	// Discover MCP server
	// First the tools
	toolsRequest := mcp.ListToolsRequest{}

	toolsList, err := mcpClient.ListTools(ctx, toolsRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to discover mcp tools: %w", err)
	}

	// After that the resources
	resourcesRequest := mcp.ListResourcesRequest{}

	resourcesList, err := mcpClient.ListResources(ctx, resourcesRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to discover MCP resources: %w", err)
	}

	// Parse the tools and resources
	// Get the first batch of tools
	availableTools := make([]*mcptypes.McpTool, 0)

	for index := range toolsList.Tools {
		tool := toolsList.Tools[index]

		// Convert parameters to JSON string
		jsonParams, err := json.Marshal(tool.InputSchema)
		if err != nil {
			jsonParams = []byte{}
		}

		var parameters map[string]any

		err = json.Unmarshal(jsonParams, &parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to parse MCP tools: %w", err)
		}

		availableTools = append(availableTools, &mcptypes.McpTool{
			Name:        tool.Name,
			Description: tool.Description,
			Parameters:  parameters,
		})
	}

	// Get the first batch of resources
	availableResources := make([]*mcptypes.McpResource, 0)

	for index := range resourcesList.Resources {
		resource := resourcesList.Resources[index]

		availableResources = append(availableResources, &mcptypes.McpResource{
			Name:        resource.Name,
			Description: resource.Description,
			URI:         resource.URI,
		})
	}

	return &mcptypes.McpServer{
		Name:      name,
		URL:       url,
		Tools:     availableTools,
		Resources: availableResources,
	}, nil
}
