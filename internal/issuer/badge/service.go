// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package badge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/agntcy/identity/internal/issuer/auth"
	"github.com/agntcy/identity/internal/issuer/badge/data"
	issdata "github.com/agntcy/identity/internal/issuer/issuer/data"
	mddata "github.com/agntcy/identity/internal/issuer/metadata/data"
	"github.com/agntcy/identity/internal/pkg/nodeapi"
	"github.com/agntcy/identity/pkg/joseutil"
	"github.com/agntcy/identity/pkg/jwk"
	"github.com/google/uuid"

	"github.com/agntcy/identity/internal/core/vc"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	internalIssuerTypes "github.com/agntcy/identity/internal/issuer/types"
)

type BadgeService interface {
	IssueBadge(
		vaultId string,
		keyId string,
		issuerId string,
		metadataId string,
		content *vctypes.CredentialContent,
		privateKey *jwk.Jwk,
	) (string, error)
	PublishBadge(
		ctx context.Context,
		vaultId string,
		keyId string,
		issuerId string,
		metadataId string,
		badge *internalIssuerTypes.Badge,
		identityNodeURL *string,
	) (*internalIssuerTypes.Badge, error)
	GetAllBadges(vaultId, keyId, issuerId, metadataId string) ([]*internalIssuerTypes.Badge, error)
	GetBadge(
		vaultId, keyId, issuerId, metadataId, badgeId string,
	) (*internalIssuerTypes.Badge, error)
	ForgetBadge(vaultId, keyId, issuerId, metadataId, badgeId string) error
}

type badgeService struct {
	badgeRepository    data.BadgeRepository
	metadataRepository mddata.MetadataRepository
	issuerRepository   issdata.IssuerRepository
	authClient         auth.Client
	nodeClientPrv      nodeapi.ClientProvider
}

func NewBadgeService(
	badgeRepository data.BadgeRepository,
	metadataRepository mddata.MetadataRepository,
	issuerRepository issdata.IssuerRepository,
	authClient auth.Client,
	nodeClientPrv nodeapi.ClientProvider,
) BadgeService {
	return &badgeService{
		badgeRepository:    badgeRepository,
		metadataRepository: metadataRepository,
		issuerRepository:   issuerRepository,
		authClient:         authClient,
		nodeClientPrv:      nodeClientPrv,
	}
}

func (s *badgeService) IssueBadge(
	vaultId string,
	keyId string,
	issuerId string,
	metadataId string,
	content *vctypes.CredentialContent,
	privateKey *jwk.Jwk,
) (string, error) {
	issuer, err := s.issuerRepository.GetIssuer(vaultId, keyId, issuerId)
	if err != nil {
		return "", err
	}

	_, err = s.metadataRepository.GetMetadata(vaultId, keyId, issuerId, metadataId)
	if err != nil {
		return "", fmt.Errorf("unable to fetch the metadata: %w", err)
	}

	if content.Type == vctypes.CREDENTIAL_CONTENT_TYPE_UNSPECIFIED {
		return "", errors.New("unsupported content type")
	}

	if privateKey == nil {
		return "", errors.New("invalid privateKey argument")
	}

	credential, err := vc.New(
		vc.WithIssuer(&issuer.Issuer),
		vc.WithCredentialContent(content),
	)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(credential)
	if err != nil {
		return "", err
	}

	signed, err := joseutil.Sign(privateKey, payload)
	if err != nil {
		return "", fmt.Errorf("unable to sign the badge: %w", err)
	}

	envelopedCredential := vctypes.EnvelopedCredential{
		EnvelopeType: vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE,
		Value:        string(signed),
	}

	badge := internalIssuerTypes.Badge{
		Id:                  uuid.New().String(),
		EnvelopedCredential: &envelopedCredential,
	}

	badgeId, err := s.badgeRepository.AddBadge(vaultId, keyId, issuerId, metadataId, &badge)
	if err != nil {
		return "", err
	}

	return badgeId, nil
}

func (s *badgeService) PublishBadge(
	ctx context.Context,
	vaultId string,
	keyId string,
	issuerId string,
	metadataId string,
	badge *internalIssuerTypes.Badge,
	identityNodeURL *string,
) (*internalIssuerTypes.Badge, error) {
	issuer, err := s.issuerRepository.GetIssuer(vaultId, keyId, issuerId)
	if err != nil {
		return nil, err
	}

	md, err := s.metadataRepository.GetMetadata(vaultId, keyId, issuerId, metadataId)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch the metadata: %w", err)
	}

	token, err := s.authClient.Authenticate(
		ctx,
		issuer,
		auth.WithIdpIssuing(md.IdpConfig),
		auth.WithSelfIssuing(vaultId, keyId, strings.TrimPrefix(md.ID, "AGNTCY-")),
	)
	if err != nil {
		return nil, err
	}

	proof := vctypes.Proof{
		Type:       "JWT",
		ProofValue: token,
	}

	iNodeURL := issuer.IdentityNodeURL
	if identityNodeURL != nil && *identityNodeURL != "" {
		iNodeURL = *identityNodeURL
	}

	client, err := s.nodeClientPrv.New(iNodeURL)
	if err != nil {
		return nil, err
	}

	err = client.PublishVerifiableCredential(badge.EnvelopedCredential, &proof)
	if err != nil {
		return nil, err
	}

	return badge, nil
}

func (s *badgeService) GetAllBadges(
	vaultId, keyId, issuerId, metadataId string,
) ([]*internalIssuerTypes.Badge, error) {
	badges, err := s.badgeRepository.GetAllBadges(vaultId, keyId, issuerId, metadataId)
	if err != nil {
		return nil, err
	}

	return badges, nil
}

func (s *badgeService) GetBadge(
	vaultId, keyId, issuerId, metadataId, badgeId string,
) (*internalIssuerTypes.Badge, error) {
	badge, err := s.badgeRepository.GetBadge(vaultId, keyId, issuerId, metadataId, badgeId)
	if err != nil {
		return nil, err
	}

	return badge, nil
}

func (s *badgeService) ForgetBadge(vaultId, keyId, issuerId, metadataId, badgeId string) error {
	err := s.badgeRepository.RemoveBadge(vaultId, keyId, issuerId, metadataId, badgeId)
	if err != nil {
		return err
	}

	return nil
}
