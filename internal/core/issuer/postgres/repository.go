// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"

	errcore "github.com/agntcy/identity/internal/core/errors"
	issuercore "github.com/agntcy/identity/internal/core/issuer"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	"github.com/agntcy/identity/internal/pkg/db"
	"gorm.io/gorm"
)

type repository struct {
	dbContext db.Context
}

// NewIssuerRepository creates a new instance of the IssuerRepository
func NewRepository(dbContext db.Context) issuercore.Repository {
	return &repository{
		dbContext,
	}
}

// CreateIssuer creates a new Issuer
func (r *repository) CreateIssuer(
	ctx context.Context,
	issuer *issuertypes.Issuer,
) (*issuertypes.Issuer, error) {
	model := newIssuerModel(issuer)

	// Create the issuer
	inserted := r.dbContext.Client().Create(model)
	if inserted.Error != nil {
		return nil, fmt.Errorf("there was an error creating the issuer: %w", inserted.Error)
	}

	return issuer, nil
}

func (r *repository) GetIssuer(
	ctx context.Context,
	commonName string,
) (*issuertypes.Issuer, error) {
	var issuer Issuer

	result := r.dbContext.Client().First(&issuer, map[string]interface{}{
		"common_name": commonName,
	})
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errcore.ErrResourceNotFound
		}

		return nil, fmt.Errorf("there was an error fetching the issuer: %w", result.Error)
	}

	return issuer.ToCoreType(), nil
}
