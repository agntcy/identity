// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package issue

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	clicache "github.com/agntcy/identity/cmd/issuer/cache"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/issuer/badge"
	"github.com/agntcy/identity/internal/issuer/badge/mcp"
	"github.com/agntcy/identity/internal/issuer/vault"
	"github.com/agntcy/identity/internal/pkg/cmdutil"
	"github.com/spf13/cobra"
)

type IssueMcpFlags struct {
	McpServerUrl  string
	McpServerName string
}

type IssueMcpCommand struct {
	cache        *clicache.Cache
	badgeService badge.BadgeService
	vaultSrv     vault.VaultService
	mcpClient    mcp.DiscoveryClient
}

func NewCmdMcp(
	cache *clicache.Cache,
	badgeService badge.BadgeService,
	vaultSrv vault.VaultService,
	mcpClient mcp.DiscoveryClient,
) *cobra.Command {
	flags := NewIssueMcpFlags()

	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Issue a badge based on an MCP server URL",
		Run: func(cmd *cobra.Command, args []string) {
			c := IssueMcpCommand{
				cache:        cache,
				badgeService: badgeService,
				vaultSrv:     vaultSrv,
				mcpClient:    mcpClient,
			}

			err := c.Run(cmd.Context(), flags)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		},
	}

	flags.AddFlags(cmd)

	return cmd
}

func NewIssueMcpFlags() *IssueMcpFlags {
	return &IssueMcpFlags{}
}

func (f *IssueMcpFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.McpServerUrl, "url", "u", "", "The URL of the MCP server")
	cmd.Flags().StringVarP(&f.McpServerName, "name", "n", "", "The name of the MCP server")
}

func (cmd *IssueMcpCommand) Run(ctx context.Context, flags *IssueMcpFlags) error {
	err := cmd.cache.ValidateForBadge()
	if err != nil {
		return fmt.Errorf("error validating local configuration: %w", err)
	}

	// if the mcp server url is not set, prompt the user for it interactively
	err = cmdutil.ScanRequiredIfNotSet(
		"URL of the MCP server you want to sign in the badge",
		&flags.McpServerUrl,
	)
	if err != nil {
		return fmt.Errorf("error reading mcp server URL: %w", err)
	}

	// if the mcp server name is not set, prompt the user for it interactively
	err = cmdutil.ScanRequiredIfNotSet(
		"Name of the MCP server you want to sign in the badge",
		&flags.McpServerName,
	)
	if err != nil {
		return fmt.Errorf("error reading mcp server name: %w", err)
	}

	// Retrieve the MCP server data
	mcpServer, err := cmd.mcpClient.Discover(ctx, flags.McpServerName, flags.McpServerUrl)
	if err != nil {
		return fmt.Errorf("error discovering MCP server: %w", err)
	}

	if mcpServer == nil {
		return fmt.Errorf("no MCP server found")
	}

	// Marshal the MCP server to JSON
	mcpServerData, err := json.Marshal(mcpServer)
	if err != nil {
		return fmt.Errorf("error marshalling MCP server: %w", err)
	}

	prvKey, err := cmd.vaultSrv.RetrievePrivKey(ctx, cmd.cache.VaultId, cmd.cache.KeyID)
	if err != nil {
		return fmt.Errorf("error retrieving public key: %w", err)
	}

	claims := vctypes.BadgeClaims{
		ID:    cmd.cache.MetadataId,
		Badge: string(mcpServerData),
	}

	badgeId, err := cmd.badgeService.IssueBadge(
		cmd.cache.VaultId,
		cmd.cache.KeyID,
		cmd.cache.IssuerId,
		cmd.cache.MetadataId,
		&vctypes.CredentialContent{
			Type:    vctypes.CREDENTIAL_CONTENT_TYPE_MCP_BADGE,
			Content: claims.ToMap(),
		},
		prvKey,
	)
	if err != nil {
		return fmt.Errorf("error issuing badge: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Issued badge with ID: %s\n", badgeId)

	// Save the badge ID to the cache
	cmd.cache.BadgeId = badgeId

	err = clicache.SaveCache(cmd.cache)
	if err != nil {
		return fmt.Errorf("error saving local configuration: %w", err)
	}

	return nil
}
