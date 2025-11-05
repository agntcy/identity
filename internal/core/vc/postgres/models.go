// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"encoding/json"
	"time"

	"github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/pkg/convertutil"
	"github.com/agntcy/identity/internal/pkg/log"
	"github.com/lib/pq"
)

type VerifiableCredential struct {
	ID                 string `gorm:"primarykey"`
	CreatedAt          time.Time
	Context            pq.StringArray `gorm:"type:text[]"`
	Type               pq.StringArray `gorm:"type:text[]"`
	Issuer             string
	CredentialSubject  json.RawMessage
	IssuanceDate       string
	ExpirationDate     string
	CredentialSchema   []*CredentialSchema `gorm:"foreignKey:VerifiableCredentialID"`
	Status             []*CredentialStatus `gorm:"foreignKey:VerifiableCredentialID"`
	Proof              *types.Proof        `gorm:"embedded;embeddedPrefix:proof_"`
	ResolverMetadataID string
}

func (vm *VerifiableCredential) ToCoreType() *types.VerifiableCredential {
	var sub map[string]any

	err := json.Unmarshal(vm.CredentialSubject, &sub)
	if err != nil {
		log.Warn(err)
	}

	return &types.VerifiableCredential{
		Context:           vm.Context,
		Type:              vm.Type,
		Issuer:            vm.Issuer,
		CredentialSubject: sub,
		ID:                vm.ID,
		IssuanceDate:      vm.IssuanceDate,
		ExpirationDate:    vm.ExpirationDate,
		CredentialSchema: convertutil.ConvertSlice(
			vm.CredentialSchema,
			func(c *CredentialSchema) *types.CredentialSchema {
				return c.ToCoreType()
			},
		),
		Status: convertutil.ConvertSlice(
			vm.Status,
			func(c *CredentialStatus) *types.CredentialStatus {
				return c.ToCoreType()
			},
		),
		Proof: vm.Proof,
	}
}

type CredentialSchema struct {
	ID                     string `gorm:"primaryKey"`
	VerifiableCredentialID string `gorm:"primaryKey"`
	Type                   string
}

func (c *CredentialSchema) ToCoreType() *types.CredentialSchema {
	return &types.CredentialSchema{
		Type: c.Type,
		ID:   c.ID,
	}
}

type CredentialStatus struct {
	ID                     string `gorm:"primaryKey"`
	VerifiableCredentialID string `gorm:"primaryKey"`
	Type                   string
	CreatedAt              time.Time
	Purpose                types.CredentialStatusPurpose
}

func (c *CredentialStatus) ToCoreType() *types.CredentialStatus {
	return &types.CredentialStatus{
		ID:        c.ID,
		Type:      c.Type,
		CreatedAt: c.CreatedAt,
		Purpose:   c.Purpose,
	}
}

func newVerifiableCredentialModel(
	src *types.VerifiableCredential,
	resolverMetadataID string,
) *VerifiableCredential {
	sub, err := json.Marshal(src.CredentialSubject)
	if err != nil {
		log.Warn(err)
	}

	return &VerifiableCredential{
		ID:                src.ID,
		CreatedAt:         time.Now().UTC(),
		Context:           src.Context,
		Type:              src.Type,
		Issuer:            src.Issuer,
		CredentialSubject: sub,
		IssuanceDate:      src.IssuanceDate,
		ExpirationDate:    src.ExpirationDate,
		CredentialSchema: convertutil.ConvertSlice(
			src.CredentialSchema,
			func(cs *types.CredentialSchema) *CredentialSchema {
				return newCredentialSchemaModel(cs, src.ID)
			},
		),
		Status: convertutil.ConvertSlice(
			src.Status,
			func(cs *types.CredentialStatus) *CredentialStatus {
				return newCredentialStatusModel(cs, src.ID)
			},
		),
		Proof:              src.Proof,
		ResolverMetadataID: resolverMetadataID,
	}
}

func newCredentialSchemaModel(src *types.CredentialSchema, vcID string) *CredentialSchema {
	return &CredentialSchema{
		ID:                     src.ID,
		Type:                   src.Type,
		VerifiableCredentialID: vcID,
	}
}

func newCredentialStatusModel(src *types.CredentialStatus, vcID string) *CredentialStatus {
	return &CredentialStatus{
		ID:                     src.ID,
		Type:                   src.Type,
		CreatedAt:              src.CreatedAt,
		Purpose:                src.Purpose,
		VerifiableCredentialID: vcID,
	}
}
