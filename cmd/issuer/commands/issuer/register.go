// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package issuer

import (
	"context"
	"fmt"
	"os"

	clicache "github.com/agntcy/identity/cmd/issuer/cache"
	coreissuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	issuersrv "github.com/agntcy/identity/internal/issuer/issuer"
	issuertypes "github.com/agntcy/identity/internal/issuer/issuer/types"
	idptypes "github.com/agntcy/identity/internal/issuer/types"
	"github.com/agntcy/identity/internal/issuer/vault"
	"github.com/agntcy/identity/internal/pkg/cmdutil"
	"github.com/agntcy/identity/internal/pkg/httputil"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

const (
	defaultNodeAddress = "http://localhost:4000"
)

type RegisterFlags struct {
	IdentityNodeURL string
	ClientID        string
	ClientSecret    string
	IssuerURL       string
	CommonName      string // Self provided common name (e.g., url, email, etc.)
	Organization    string
	SubOrganization string
}

type RegisterCommand struct {
	cache         *clicache.Cache
	issuerService issuersrv.IssuerService
	vaultSrv      vault.VaultService
}

func NewCmdRegister(
	cache *clicache.Cache,
	issuerService issuersrv.IssuerService,
	vaultSrv vault.VaultService,
) *cobra.Command {
	flags := NewRegisterFlags()

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register as an Issuer",
		Long:  "Register with an identity provider, such as DUO or Okta, to manage your Agent and MCP identities",
		Run: func(cmd *cobra.Command, args []string) {
			c := RegisterCommand{
				cache:         cache,
				issuerService: issuerService,
				vaultSrv:      vaultSrv,
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

func NewRegisterFlags() *RegisterFlags {
	return &RegisterFlags{}
}

func (f *RegisterFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().
		StringVarP(&f.IdentityNodeURL, "identity-node-address", "i", "", "Identity node address")
	cmd.Flags().
		StringVarP(&f.CommonName, "common-name", "n", "", "Self provided common name (e.g., url, email, etc.)")
	cmd.Flags().StringVarP(&f.ClientID, "idp-client-id", "c", "", "IdP client ID")
	cmd.Flags().StringVarP(&f.ClientSecret, "idp-client-secret", "s", "", "IdP client secret")
	cmd.Flags().StringVarP(&f.IssuerURL, "idp-issuer-url", "u", "", "IdP issuer URL")
	cmd.Flags().StringVarP(&f.Organization, "organization", "o", "", "Organization name")
	cmd.Flags().StringVarP(&f.SubOrganization, "sub-organization", "b", "", "Sub-organization name")
}

func (cmd *RegisterCommand) Run(ctx context.Context, flags *RegisterFlags) error {
	err := cmd.cache.ValidateForIssuer()
	if err != nil {
		return fmt.Errorf("error validating local configuration: %w", err)
	}

	err = cmd.validateFlags(flags)
	if err != nil {
		return err
	}

	commonName := flags.CommonName
	issuerAuthType := coreissuertypes.ISSUER_AUTH_TYPE_SELF
	id := uuid.NewString()

	var idpConfig *idptypes.IdpConfig

	// If the common name is not set, use the IdP configuration
	if flags.CommonName == "" {
		idpConfig = &idptypes.IdpConfig{
			ClientId:     flags.ClientID,
			ClientSecret: flags.ClientSecret,
			IssuerUrl:    flags.IssuerURL,
		}

		// extract the root url from the issuer URL as the common name
		commonName = httputil.Hostname(flags.IssuerURL)
		if commonName == "" {
			return fmt.Errorf("error extracting common name from issuer URL")
		}

		id = flags.ClientID
		issuerAuthType = coreissuertypes.ISSUER_AUTH_TYPE_IDP
	}

	pubKey, err := cmd.vaultSrv.RetrievePubKey(ctx, cmd.cache.VaultId, cmd.cache.KeyID)
	if err != nil {
		return fmt.Errorf("error retreiving public key: %w", err)
	}

	issuer := issuertypes.Issuer{
		Issuer: coreissuertypes.Issuer{
			Organization:    flags.Organization,
			SubOrganization: flags.SubOrganization,
			CommonName:      commonName,
			PublicKey:       pubKey,
			Verified:        flags.CommonName == "",
			AuthType:        issuerAuthType,
		},
		ID:              id,
		IdentityNodeURL: flags.IdentityNodeURL,
		IdpConfig:       idpConfig,
	}

	issuerId, err := cmd.issuerService.RegisterIssuer(
		ctx,
		cmd.cache.VaultId,
		cmd.cache.KeyID,
		&issuer,
	)
	if err != nil {
		return fmt.Errorf("error registering as an Issuer: %w", err)
	}

	fmt.Fprintf(
		os.Stdout,
		"\nSuccessfully registered as an Issuer with:\n- ID: %s\n- Common Name: %s\n",
		issuerId,
		commonName,
	)
	fmt.Fprintf(
		os.Stdout,
		"\nYou can now access the Issuer's Well-Known Public Key at: "+
			"%s/v1alpha1/issuer/%s/.well-known/jwks.json\n",
		flags.IdentityNodeURL,
		commonName,
	)

	// Update the cache with the new issuer ID
	cmd.cache.IssuerId = issuerId

	err = clicache.SaveCache(cmd.cache)
	if err != nil {
		return fmt.Errorf("error saving local configuration: %w", err)
	}

	return nil
}

func (cmd *RegisterCommand) validateFlags(flags *RegisterFlags) error {
	// if the identity node address is not set, prompt the user for it interactively
	err := cmdutil.ScanWithDefaultIfNotSet(
		"Identity node address",
		defaultNodeAddress,
		&flags.IdentityNodeURL,
	)
	if err != nil {
		return fmt.Errorf("error reading identity node address: %w", err)
	}

	// if the common name is not set, prompt the user for it interactively
	if flags.CommonName == "" && cmd.noIdpFlagsSet(flags) {
		err := cmdutil.ScanOptional(
			"Common name (e.g., url, email, etc.), leave empty to use IdP",
			&flags.CommonName,
		)
		if err != nil {
			return fmt.Errorf("error reading common name: %w", err)
		}
	}

	// if self provided common name is not set, ask for IdP client ID, secret, and issuer URL
	if flags.CommonName == "" {
		err := cmd.scanIdpFlags(flags)
		if err != nil {
			return err
		}
	}

	// if the organization is not set, prompt the user for it interactively
	err = cmdutil.ScanRequiredIfNotSet("Organization name", &flags.Organization)
	if err != nil {
		return fmt.Errorf("error reading organization name: %w", err)
	}

	// if the sub-organization is not set, prompt the user for it interactively
	err = cmdutil.ScanWithDefaultIfNotSet(
		"Sub-organization name",
		flags.Organization,
		&flags.SubOrganization,
	)
	if err != nil {
		return fmt.Errorf("error reading sub-organization name: %w", err)
	}

	return nil
}

func (cmd *RegisterCommand) noIdpFlagsSet(flags *RegisterFlags) bool {
	return flags.ClientID == "" && flags.ClientSecret == "" && flags.IssuerURL == ""
}

func (cmd *RegisterCommand) scanIdpFlags(flags *RegisterFlags) error {
	// if the client ID is not set, prompt the user for it interactively
	err := cmdutil.ScanRequiredIfNotSet("IdP client ID", &flags.ClientID)
	if err != nil {
		return fmt.Errorf("error reading IdP client ID: %w", err)
	}

	// if the client secret is not set, prompt the user for it interactively
	err = cmdutil.ScanRequiredIfNotSet("IdP client secret", &flags.ClientSecret)
	if err != nil {
		return fmt.Errorf("error reading IdP client secret: %w", err)
	}

	// if the issuer URL is not set, prompt the user for it interactively
	err = cmdutil.ScanRequiredIfNotSet("IdP issuer URL", &flags.IssuerURL)
	if err != nil {
		return fmt.Errorf("error reading IdP issuer URL: %w", err)
	}

	return nil
}
