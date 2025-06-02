// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	clicache "github.com/agntcy/identity/cmd/issuer/cache"
	mdsrv "github.com/agntcy/identity/internal/issuer/metadata"
	issuerTypes "github.com/agntcy/identity/internal/issuer/types"
	"github.com/agntcy/identity/internal/pkg/cmdutil"
)

type GenerateFlags struct {
	IdpClientID     string
	IdpClientSecret string
	IdpIssuerURL    string
}

type GenerateCommand struct {
	cache           *clicache.Cache
	metadataService mdsrv.MetadataService
}

func NewCmdGenerate(
	cache *clicache.Cache,
	metadataService mdsrv.MetadataService,
) *cobra.Command {
	flags := NewGenerateFlags()

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate new metadata for your Agent and MCP Server identities",
		Run: func(cmd *cobra.Command, args []string) {
			c := GenerateCommand{
				cache:           cache,
				metadataService: metadataService,
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

func NewGenerateFlags() *GenerateFlags {
	return &GenerateFlags{}
}

func (f *GenerateFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.IdpClientID, "idp-client-id", "c", "", "IDP Client ID")
	cmd.Flags().StringVarP(&f.IdpClientSecret, "idp-client-secret", "s", "", "IDP Client Secret")
	cmd.Flags().StringVarP(&f.IdpIssuerURL, "idp-issuer-url", "u", "", "IDP Issuer URL")
}

func (cmd *GenerateCommand) Run(ctx context.Context, flags *GenerateFlags) error {
	err := cmd.cache.ValidateForMetadata()
	if err != nil {
		return fmt.Errorf("error validating local configuration: %w", err)
	}

	// if the idp client id is not set, prompt the user for it interactively
	if flags.IdpClientID == "" {
		err := cmdutil.ScanRequired("IDP Client ID", &flags.IdpClientID)
		if err != nil {
			return fmt.Errorf("error reading IDP Client ID: %w", err)
		}
	}

	// if the idp client secret is not set, prompt the user for it interactively
	if flags.IdpClientSecret == "" {
		err := cmdutil.ScanRequired("IDP Client Secret", &flags.IdpClientSecret)
		if err != nil {
			return fmt.Errorf("error reading IDP Client Secret: %w", err)
		}
	}

	// if the idp issuer url is not set, prompt the user for it interactively
	if flags.IdpIssuerURL == "" {
		err := cmdutil.ScanRequired("IDP Issuer URL", &flags.IdpIssuerURL)
		if err != nil {
			return fmt.Errorf("error reading IDP Issuer URL: %w", err)
		}
	}

	idpConfig := issuerTypes.IdpConfig{
		ClientId:     flags.IdpClientID,
		ClientSecret: flags.IdpClientSecret,
		IssuerUrl:    flags.IdpIssuerURL,
	}

	metadataId, err := cmd.metadataService.GenerateMetadata(
		ctx,
		cmd.cache.VaultId,
		cmd.cache.KeyID,
		cmd.cache.IssuerId,
		&idpConfig,
	)
	if err != nil {
		return fmt.Errorf("error generating metadata: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Generated metadata with ID: %s\n", metadataId)

	// Update the cache with the new metadata ID
	cmd.cache.MetadataId = metadataId

	err = clicache.SaveCache(cmd.cache)
	if err != nil {
		return fmt.Errorf("error saving local configuration: %w", err)
	}

	return nil
}
