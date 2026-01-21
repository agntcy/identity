// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"net/mail"

	"github.com/agntcy/identity/pkg/jwk"
)

// IssuerAuthType represents the type of authentication mechanism used by the issuer.
type IssuerAuthType int

const (
	// ISSUER_AUTH_TYPE_UNSPECIFIED represents an unspecified or unknown authentication type.
	ISSUER_AUTH_TYPE_UNSPECIFIED IssuerAuthType = iota

	// ISSUER_AUTH_TYPE_IDP indicates that the issuer uses an external Identity Provider (IDP)
	// to authenticate
	ISSUER_AUTH_TYPE_IDP

	// ISSUER_AUTH_TYPE_SELF indicates that the issuer uses a self-issued key for authentication.
	// This is typically used in scenarios where the issuer doesn't rely on an IdP.
	ISSUER_AUTH_TYPE_SELF

	// ISSUER_AUTH_TYPE_DID indicates that the issuer uses a Decentralized Identifier (DID)
	// for authentication. The DID is resolved to obtain verification methods.
	ISSUER_AUTH_TYPE_DID
)

// A Identity Issuer
type Issuer struct {
	// The organization of the issuer
	Organization string `json:"organization,omitempty" protobuf:"bytes,1,opt,name=organization"`

	// The sub organization of the issuer
	SubOrganization string `json:"subOrganization,omitempty" protobuf:"bytes,2,opt,name=sub_organization"`

	// The common name of the issuer
	// Could be a FQDN or a FQDA
	CommonName string `json:"commonName,omitempty" protobuf:"bytes,3,opt,name=common_name"`

	// This will be set to true when issuer provides a valid proof of ownership
	// of the common name on registration
	Verified bool `json:"verified,omitempty" protobuf:"varint,6,opt,name=verified"`

	// This field is optional
	// The keys of the issuer in JWK format
	// The public key is used to verify the signature of the different claims
	PublicKey *jwk.Jwk `json:"publicKey,omitempty" protobuf:"bytes,4,opt,name=public_key"`

	// This field is optional
	// The private key of the issuer in JWK format
	PrivateKey *jwk.Jwk `json:"privateKey,omitempty" protobuf:"bytes,5,opt,name=private_key"`

	// This field specifies the authentication mechanism used by the issuer.
	// It determines whether the issuer uses an external Identity Provider (IDP)
	// or a self-issued key for authentication.
	AuthType IssuerAuthType `json:"authType,omitempty" protobuf:"varint,7,opt,name=auth_type"`
}

// ValidateCommonName validates the common name of the issuer
func (i *Issuer) ValidateCommonName() error {
	if i.CommonName == "" {
		return fmt.Errorf("common name is empty")
	}

	// Validate FQDA
	_, fqdaErr := mail.ParseAddress(i.CommonName)

	// Validate FQDN
	_, fqdnErr := mail.ParseAddress("test@" + i.CommonName)

	if fqdaErr != nil && fqdnErr != nil {
		return fmt.Errorf("common name is not a valid FQDA or FQDN: %s", i.CommonName)
	}

	return nil
}
