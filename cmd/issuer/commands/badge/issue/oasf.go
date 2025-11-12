// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package issue

import (
	"context"
	"fmt"
	"os"

	cliCache "github.com/agntcy/identity/cmd/issuer/cache"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/issuer/badge"
	"github.com/agntcy/identity/internal/issuer/vault"
	"github.com/agntcy/identity/internal/pkg/cmdutil"
	"github.com/spf13/cobra"
)

type IssueOasfFlags struct {
	OasfPath string
}

type IssueOasfCommand struct {
	cache        *cliCache.Cache
	badgeService badge.BadgeService
	vaultSrv     vault.VaultService
}

func NewCmdIssueOasf(
	cache *cliCache.Cache,
	badgeService badge.BadgeService,
	vaultSrv vault.VaultService,
) *cobra.Command {
	flags := NewIssueOasfFlags()

	cmd := &cobra.Command{
		Use:   "oasf",
		Short: "Issue a badge based on a local OASF file",
		Run: func(cmd *cobra.Command, args []string) {
			c := IssueOasfCommand{
				cache:        cache,
				badgeService: badgeService,
				vaultSrv:     vaultSrv,
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

func NewIssueOasfFlags() *IssueOasfFlags {
	return &IssueOasfFlags{}
}

func (f *IssueOasfFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&f.OasfPath,
		"oasf-path",
		"o",
		"",
		"The file path to the OASF you want to sign in the badge",
	)
}

func (cmd *IssueOasfCommand) Run(ctx context.Context, flags *IssueOasfFlags) error {
	err := cmd.cache.ValidateForBadge()
	if err != nil {
		return fmt.Errorf("error validating local configuration: %w", err)
	}

	// if the file path is not set, prompt the user for it interactively
	err = cmdutil.ScanRequiredIfNotSet(
		"Full file path to the OASF you want to sign in the badge",
		&flags.OasfPath,
	)
	if err != nil {
		return fmt.Errorf("error reading OASF path: %w", err)
	}

	badgeContentData, err := os.ReadFile(flags.OasfPath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	prvKey, err := cmd.vaultSrv.RetrievePrivKey(ctx, cmd.cache.VaultId, cmd.cache.KeyID)
	if err != nil {
		return fmt.Errorf("error retreiving public key: %w", err)
	}

	claims := vctypes.BadgeClaims{
		ID:    cmd.cache.MetadataId,
		Badge: string(badgeContentData),
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

	err = cliCache.SaveCache(cmd.cache)
	if err != nil {
		return fmt.Errorf("error saving local configuration: %w", err)
	}

	return nil
}
