// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package issue

import (
	"context"
	"fmt"
	"os"

	clicache "github.com/agntcy/identity/cmd/issuer/cache"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/issuer/badge"
	"github.com/agntcy/identity/internal/issuer/vault"
	"github.com/agntcy/identity/internal/pkg/cmdutil"
	"github.com/spf13/cobra"

	"github.com/agntcy/identity/internal/issuer/badge/a2a"
)

type IssueA2AFlags struct {
	A2AWellKnown string
}

type IssueA2ACommand struct {
	cache        *clicache.Cache
	badgeService badge.BadgeService
	vaultSrv     vault.VaultService
	a2aClient    a2a.DiscoveryClient
}

func NewCmdIssueA2A(
	cache *clicache.Cache,
	badgeService badge.BadgeService,
	vaultSrv vault.VaultService,
	a2aClient a2a.DiscoveryClient,
) *cobra.Command {
	flags := NewIssueA2AFlags()

	cmd := &cobra.Command{
		Use:   "a2a",
		Short: "Issue a badge based on a local file",
		Run: func(cmd *cobra.Command, args []string) {
			c := IssueA2ACommand{
				cache:        cache,
				badgeService: badgeService,
				vaultSrv:     vaultSrv,
				a2aClient:    a2aClient,
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

func NewIssueA2AFlags() *IssueA2AFlags {
	return &IssueA2AFlags{}
}

func (f *IssueA2AFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&f.A2AWellKnown,
		"url",
		"u",
		"",
		"The well-known URL of the A2A agent you want to sign in the badge",
	)
}

func (cmd *IssueA2ACommand) Run(ctx context.Context, flags *IssueA2AFlags) error {
	err := cmd.cache.ValidateForBadge()
	if err != nil {
		return fmt.Errorf("error validating local configuration: %w", err)
	}

	// if the mcp server url is not set, prompt the user for it interactively
	err = cmdutil.ScanRequiredIfNotSet(
		"Well-known URL of the A2A agent you want to sign in the badge",
		&flags.A2AWellKnown,
	)
	if err != nil {
		return fmt.Errorf("error reading A2A well-known URL: %w", err)
	}

	// Convert the badge value to a string
	agentCard, err := cmd.a2aClient.Discover(ctx, flags.A2AWellKnown)
	if err != nil {
		return fmt.Errorf("error discovering A2A agent: %w", err)
	}

	prvKey, err := cmd.vaultSrv.RetrievePrivKey(
		ctx,
		cmd.cache.VaultId,
		cmd.cache.KeyID,
	)
	if err != nil {
		return fmt.Errorf("error retrieving public key: %w", err)
	}

	claims := vctypes.BadgeClaims{
		ID:    cmd.cache.MetadataId,
		Badge: agentCard,
	}

	badgeId, err := cmd.badgeService.IssueBadge(
		cmd.cache.VaultId,
		cmd.cache.KeyID,
		cmd.cache.IssuerId,
		cmd.cache.MetadataId,
		&vctypes.CredentialContent{
			Type:    vctypes.CREDENTIAL_CONTENT_TYPE_AGENT_BADGE,
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
