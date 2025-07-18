// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"context"
	"fmt"
	"os"

	clicache "github.com/agntcy/identity/cmd/issuer/cache"
	vaultsrv "github.com/agntcy/identity/internal/issuer/vault"
	"github.com/agntcy/identity/internal/pkg/cmdutil"
	"github.com/spf13/cobra"
)

type ForgetFlags struct {
	VaultID string
}

type ForgetCommand struct {
	vaultService vaultsrv.VaultService
}

func NewCmdForget(vaultService vaultsrv.VaultService) *cobra.Command {
	flags := NewForgetFlags()

	cmd := &cobra.Command{
		Use:   "forget",
		Short: "Forget a vault configuration",
		Run: func(cmd *cobra.Command, args []string) {
			c := ForgetCommand{
				vaultService: vaultService,
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

func NewForgetFlags() *ForgetFlags {
	return &ForgetFlags{}
}

func (f *ForgetFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.VaultID, "vault-id", "v", "", "The ID of the vault to forget")
}

func (cmd *ForgetCommand) Run(ctx context.Context, flags *ForgetFlags) error {
	// if the vault id is not set, prompt the user for it interactively
	err := cmdutil.ScanRequiredIfNotSet("Vault ID to forget", &flags.VaultID)
	if err != nil {
		return fmt.Errorf("error reading vault ID: %w", err)
	}

	err = cmd.vaultService.ForgetVault(flags.VaultID)
	if err != nil {
		return fmt.Errorf("error forgetting vault: %w", err)
	}

	// Remove the cache
	err = clicache.ClearCache()
	if err != nil {
		return fmt.Errorf("error removing local configuration: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Forgot vault with ID: %s\n", flags.VaultID)

	return nil
}
