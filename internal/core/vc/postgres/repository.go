// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"

	errcore "github.com/agntcy/identity/internal/core/errors"
	vccore "github.com/agntcy/identity/internal/core/vc"
	"github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/pkg/db"
	"gorm.io/gorm"
)

type vcPostgresRepository struct {
	dbContext db.Context
}

func NewRepository(dbContext db.Context) vccore.Repository {
	return &vcPostgresRepository{
		dbContext: dbContext,
	}
}

func (r *vcPostgresRepository) Create(
	ctx context.Context,
	credential *types.VerifiableCredential,
	resolverMetadataID string,
) (*types.VerifiableCredential, error) {
	model := newVerifiableCredentialModel(credential, resolverMetadataID)

	result := r.dbContext.Client().Create(model)
	if result.Error != nil {
		return nil, fmt.Errorf("there was an error creating the verifiable credential: %w", result.Error)
	}

	return credential, nil
}

func (r *vcPostgresRepository) Update(
	ctx context.Context,
	credential *types.VerifiableCredential,
	resolverMetadataID string,
) (*types.VerifiableCredential, error) {
	model := newVerifiableCredentialModel(credential, resolverMetadataID)

	err := r.dbContext.Client().Save(model).Error
	if err != nil {
		return nil, fmt.Errorf("there was an error updating the verifiable credential: %w", err)
	}

	return credential, nil
}

func (r *vcPostgresRepository) GetByResolverMetadata(
	ctx context.Context,
	resolverMetadataID string,
) ([]*types.VerifiableCredential, error) {
	var storedVCs []*VerifiableCredential

	result := r.dbContext.Client().
		Preload("Status").
		Where("resolver_metadata_id = ?", resolverMetadataID).
		Order("issuance_date DESC").
		Find(&storedVCs)
	if result.Error != nil {
		return nil, fmt.Errorf("there was an error fetching the verifiable credentials: %w", result.Error)
	}

	vcs := make([]*types.VerifiableCredential, 0, len(storedVCs))
	for _, vc := range storedVCs {
		vcs = append(vcs, vc.ToCoreType())
	}

	return vcs, nil
}

func (r *vcPostgresRepository) GetByID(
	ctx context.Context,
	id string,
) (*types.VerifiableCredential, error) {
	var vc VerifiableCredential

	err := r.dbContext.Client().Preload("Status").Where("id = ?", id).First(&vc).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errcore.ErrResourceNotFound
		}

		return nil, fmt.Errorf("there was an error fetching the verifiable credential: %w", err)
	}

	return vc.ToCoreType(), nil
}
