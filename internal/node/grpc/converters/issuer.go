// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package converters

import (
	coreapi "github.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	"github.com/agntcy/identity/internal/pkg/ptrutil"
)

func ToIssuer(src *coreapi.Issuer) *issuertypes.Issuer {
	if src == nil {
		return nil
	}

	return &issuertypes.Issuer{
		Organization:    ptrutil.DerefStr(src.Organization),
		SubOrganization: ptrutil.DerefStr(src.SubOrganization),
		CommonName:      ptrutil.DerefStr(src.CommonName),
		PublicKey:       ToJwk(src.PublicKey),
		AuthType:        issuertypes.IssuerAuthType(ptrutil.Derefrence(src.AuthType, 0)),
	}
}
