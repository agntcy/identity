// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package node_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	errcore "github.com/agntcy/identity/internal/core/errors"
	errtesting "github.com/agntcy/identity/internal/core/errors/testing"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	idcore "github.com/agntcy/identity/internal/core/id"
	idtesting "github.com/agntcy/identity/internal/core/id/testing"
	idtypes "github.com/agntcy/identity/internal/core/id/types"
	issuertesting "github.com/agntcy/identity/internal/core/issuer/testing"
	issuertypes "github.com/agntcy/identity/internal/core/issuer/types"
	issuerverif "github.com/agntcy/identity/internal/core/issuer/verification"
	verificationtesting "github.com/agntcy/identity/internal/core/issuer/verification/testing"
	vcmocks "github.com/agntcy/identity/internal/core/vc/mocks"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
	"github.com/agntcy/identity/internal/node"
	jwktype "github.com/agntcy/identity/pkg/jwk"
	"github.com/agntcy/identity/pkg/oidc"
	oidctesting "github.com/agntcy/identity/pkg/oidc/testing"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var validParsedJWT = &oidc.ParsedJWT{
	Provider: oidc.DuoProviderName,
	Claims: &oidc.Claims{
		Issuer:  "http://" + verificationtesting.ValidProofIssuer,
		Subject: verificationtesting.ValidProofSub,
	},
	CommonName: verificationtesting.ValidProofIssuer,
}

var invalidParsedJWT = &oidc.ParsedJWT{
	Provider: oidc.DuoProviderName,
	Claims: &oidc.Claims{
		Subject: verificationtesting.ValidProofSub,
		Issuer:  "INVALID",
	},
}

func TestPublishVC(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	vcRepo := vcmocks.NewRepository(t)
	vcRepo.EXPECT().Create(t.Context(), mock.Anything, mock.Anything).Return(nil, nil)

	verifSrv := issuerverif.NewService(
		oidctesting.NewFakeParser(validParsedJWT, nil),
		issuerRepo,
	)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)

	envelope := generateValidVC(t, idRepo, issuer)

	err := sut.Publish(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	assert.NoError(t, err)
}

func TestPublishVC_Should_Return_Invalid_Credential_Format_Error(t *testing.T) {
	t.Parallel()

	sut := node.NewVerifiableCredentialService(nil, nil, nil)
	invalidEnvelope := &vctypes.EnvelopedCredential{
		Value: "",
	}

	err := sut.Publish(t.Context(), invalidEnvelope, &vctypes.Proof{})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT)
}

func TestPublishVC_Should_Return_Invalid_Proof_Error_If_Empty(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
	vcRepo := vcmocks.NewRepository(t)
	verifSrv := issuerverif.NewService(oidctesting.NewFakeParser(nil, nil), nil)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	envelope := generateValidVC(t, idRepo, &issuertypes.Issuer{CommonName: "issuer"})

	err := sut.Publish(t.Context(), envelope, nil)

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
}

func TestPublishVC_Should_Return_Invalid_Proof_Error(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
	vcRepo := vcmocks.NewRepository(t)
	verifSrv := issuerverif.NewService(oidctesting.NewFakeParser(nil, errors.New("")), nil)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	envelope := generateValidVC(t, idRepo, &issuertypes.Issuer{CommonName: "issuer"})
	invalidProof := &vctypes.Proof{Type: "JWT"}

	err := sut.Publish(t.Context(), envelope, invalidProof)

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
}

func TestPublishVC_Should_Return_Issuer_Not_Registered(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	vcRepo := vcmocks.NewRepository(t)
	verifSrv := issuerverif.NewService(
		oidctesting.NewFakeParser(invalidParsedJWT, nil),
		issuerRepo,
	)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)
	envelope := generateValidVC(t, idRepo, issuer)

	err := sut.Publish(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_ISSUER_NOT_REGISTERED)
}

func TestGetWellKnown_Should_Return_Items(t *testing.T) {
	t.Parallel()

	resolverMetadatID := "my-id"
	validVC := &vctypes.VerifiableCredential{
		ID:                uuid.NewString(),
		CredentialSubject: map[string]any{"id": resolverMetadatID},
		Proof:             &vctypes.Proof{Type: "JWT", ProofValue: "PROOF"},
	}
	vcRepo := vcmocks.NewRepository(t)
	vcRepo.EXPECT().
		GetByResolverMetadata(t.Context(), resolverMetadatID).
		Return([]*vctypes.VerifiableCredential{validVC}, nil)
	sut := node.NewVerifiableCredentialService(nil, nil, vcRepo)

	actual, err := sut.GetVcs(t.Context(), resolverMetadatID)

	assert.NoError(t, err)
	assert.Len(t, actual, 1)
	assert.Equal(t, vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE, actual[0].EnvelopeType)
	assert.Equal(t, validVC.Proof.ProofValue, actual[0].Value)
}

func TestVerifyVC_Should_Succeed(t *testing.T) {
	t.Parallel()

	credential := &vctypes.VerifiableCredential{
		ID: "VC_ID",
		CredentialSubject: map[string]any{
			"id": "DUO-" + verificationtesting.ValidProofSub,
		},
	}
	privKey, pubKey, _ := genKey()
	sut := setupVcServiceWithResolverMD(t, pubKey)
	envelope, err := signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	_ = sut.Publish(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	result, err := sut.Verify(t.Context(), envelope)

	assert.NoError(t, err)
	assert.Empty(t, result.Errors)
	assert.Empty(t, result.Warnings)
}

func TestVerifyVC_Should_Fail_When_Revoked(t *testing.T) {
	t.Parallel()

	credential := &vctypes.VerifiableCredential{
		ID: "VC_ID",
		CredentialSubject: map[string]any{
			"id": "DUO-" + verificationtesting.ValidProofSub,
		},
		Status: []*vctypes.CredentialStatus{
			{
				Purpose: vctypes.CREDENTIAL_STATUS_PURPOSE_REVOCATION,
			},
		},
	}
	privKey, pubKey, _ := genKey()
	sut := setupVcServiceWithResolverMD(t, pubKey)
	envelope, err := signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	_ = sut.Publish(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	result, err := sut.Verify(t.Context(), envelope)

	assert.NoError(t, err)
	assert.Equal(t, result.Warnings[0].Reason, errtypes.ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED)
}

func TestRevokeVC_Should_Succeed(t *testing.T) {
	t.Parallel()

	credential := &vctypes.VerifiableCredential{
		ID: "VC_ID",
		CredentialSubject: map[string]any{
			"id": "DUO-" + verificationtesting.ValidProofSub,
		},
	}
	privKey, pubKey, _ := genKey()
	resolverMD := generateValidResolverMD(t, pubKey)
	idRepo := idtesting.NewFakeIdRepository()
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	vcRepo := vcmocks.NewRepository(t)
	vcRepo.EXPECT().Create(t.Context(), mock.Anything, mock.Anything).Return(nil, nil)
	vcRepo.EXPECT().GetByID(t.Context(), credential.ID).Return(&vctypes.VerifiableCredential{}, nil)
	vcRepo.EXPECT().Update(t.Context(), mock.Anything, resolverMD.ID).Return(credential, nil)

	verifSrv := issuerverif.NewService(
		oidctesting.NewFakeParser(validParsedJWT, nil),
		issuerRepo,
	)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)
	_, _ = idRepo.CreateID(t.Context(), resolverMD, issuer)
	envelope, err := signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	_ = sut.Publish(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	// Revoke
	credential.Status = []*vctypes.CredentialStatus{
		{
			Purpose: vctypes.CREDENTIAL_STATUS_PURPOSE_REVOCATION,
		},
	}
	envelope, err = signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	err = sut.Revoke(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	assert.NoError(t, err)
}

func TestRevokeVC_Should_Fail_When_VC_Not_Found(t *testing.T) {
	t.Parallel()

	credential := &vctypes.VerifiableCredential{
		ID: "VC_ID",
		CredentialSubject: map[string]any{
			"id": "DUO-" + verificationtesting.ValidProofSub,
		},
	}
	privKey, pubKey, _ := genKey()

	idRepo := idtesting.NewFakeIdRepository()
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	vcRepo := vcmocks.NewRepository(t)
	vcRepo.EXPECT().Create(t.Context(), mock.Anything, mock.Anything).Return(nil, nil)

	verifSrv := issuerverif.NewService(
		oidctesting.NewFakeParser(validParsedJWT, nil),
		issuerRepo,
	)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)

	resolverMD := generateValidResolverMD(t, pubKey)
	_, _ = idRepo.CreateID(t.Context(), resolverMD, issuer)

	envelope, err := signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	_ = sut.Publish(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	// Revoke
	credential.ID = "WRONG_ID"
	credential.Status = []*vctypes.CredentialStatus{
		{
			Purpose: vctypes.CREDENTIAL_STATUS_PURPOSE_REVOCATION,
		},
	}
	vcRepo.EXPECT().GetByID(t.Context(), credential.ID).Return(nil, errcore.ErrResourceNotFound)
	envelope, err = signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	err = sut.Revoke(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	assert.Error(t, err)
	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL)
}

func TestRevoke_Should_Fail_When_VC_Already_Revoked(t *testing.T) {
	t.Parallel()

	credential := &vctypes.VerifiableCredential{
		ID: "VC_ID",
		CredentialSubject: map[string]any{
			"id": "DUO-" + verificationtesting.ValidProofSub,
		},
		Status: []*vctypes.CredentialStatus{
			{
				Purpose: vctypes.CREDENTIAL_STATUS_PURPOSE_REVOCATION,
			},
		},
	}
	privKey, pubKey, _ := genKey()
	idRepo := idtesting.NewFakeIdRepository()
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	vcRepo := vcmocks.NewRepository(t)
	vcRepo.EXPECT().Create(t.Context(), mock.Anything, mock.Anything).Return(nil, nil)
	vcRepo.EXPECT().GetByID(t.Context(), credential.ID).Return(credential, nil)

	verifSrv := issuerverif.NewService(
		oidctesting.NewFakeParser(validParsedJWT, nil),
		issuerRepo,
	)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)

	resolverMD := generateValidResolverMD(t, pubKey)
	_, _ = idRepo.CreateID(t.Context(), resolverMD, issuer)
	envelope, err := signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	_ = sut.Publish(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	// Revoke
	credential.Status = []*vctypes.CredentialStatus{
		{
			Purpose: vctypes.CREDENTIAL_STATUS_PURPOSE_REVOCATION,
		},
	}
	envelope, err = signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	err = sut.Revoke(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	assert.Error(t, err)
	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED)
}

func TestRevokeVC_Should_Return_Invalid_Credential_Format_Error(t *testing.T) {
	t.Parallel()

	sut := node.NewVerifiableCredentialService(nil, nil, nil)
	invalidEnvelope := &vctypes.EnvelopedCredential{
		Value: "",
	}

	err := sut.Revoke(t.Context(), invalidEnvelope, &vctypes.Proof{})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT)
}

func TestRevokeVC_Should_Return_Invalid_Proof_Error_If_Empty(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
	vcRepo := vcmocks.NewRepository(t)
	verifSrv := issuerverif.NewService(oidctesting.NewFakeParser(nil, nil), nil)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	envelope := generateValidVC(t, idRepo, &issuertypes.Issuer{CommonName: "issuer"})

	err := sut.Revoke(t.Context(), envelope, nil)

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
}

func TestRevokeVC_Should_Return_Invalid_Proof_Error(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
	vcRepo := vcmocks.NewRepository(t)
	verifSrv := issuerverif.NewService(oidctesting.NewFakeParser(nil, errors.New("")), nil)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	envelope := generateValidVC(t, idRepo, &issuertypes.Issuer{CommonName: "issuer"})
	invalidProof := &vctypes.Proof{Type: "JWT"}

	err := sut.Revoke(t.Context(), envelope, invalidProof)

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_PROOF)
}

func TestRevokeVC_Should_Return_Issuer_Not_Registered(t *testing.T) {
	t.Parallel()

	idRepo := idtesting.NewFakeIdRepository()
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	vcRepo := vcmocks.NewRepository(t)
	verifSrv := issuerverif.NewService(
		oidctesting.NewFakeParser(invalidParsedJWT, nil),
		issuerRepo,
	)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)
	envelope := generateValidVC(t, idRepo, issuer)

	err := sut.Revoke(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_ISSUER_NOT_REGISTERED)
}

func TestRevoke_Should_Fail_When_Status_Does_Not_Have_Revocation(t *testing.T) {
	t.Parallel()

	credential := &vctypes.VerifiableCredential{
		ID: "VC_ID",
		CredentialSubject: map[string]any{
			"id": "DUO-" + verificationtesting.ValidProofSub,
		},
	}
	privKey, pubKey, _ := genKey()
	sut := setupVcServiceWithResolverMD(t, pubKey)

	envelope, err := signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	_ = sut.Publish(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	// Revoke
	credential.Status = []*vctypes.CredentialStatus{}

	envelope, err = signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	err = sut.Revoke(t.Context(), envelope, &vctypes.Proof{Type: "JWT"})

	assert.Error(t, err)
	errtesting.AssertErrorInfoReason(t, err, errtypes.ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL)
}

func setupVcServiceWithResolverMD(t *testing.T, pubKey *jwktype.Jwk) node.VerifiableCredentialService {
	t.Helper()

	idRepo := idtesting.NewFakeIdRepository()
	issuerRepo := issuertesting.NewFakeIssuerRepository()
	vcRepo := vcmocks.NewRepository(t)
	vcRepo.EXPECT().Create(t.Context(), mock.Anything, mock.Anything).Return(nil, nil)

	verifSrv := issuerverif.NewService(
		oidctesting.NewFakeParser(validParsedJWT, nil),
		issuerRepo,
	)
	sut := node.NewVerifiableCredentialService(idRepo, verifSrv, vcRepo)
	issuer := &issuertypes.Issuer{
		CommonName:   verificationtesting.ValidProofIssuer,
		Organization: "Some Org",
	}
	_, _ = issuerRepo.CreateIssuer(t.Context(), issuer)

	resolverMD := generateValidResolverMD(t, pubKey)
	_, _ = idRepo.CreateID(t.Context(), resolverMD, issuer)

	return sut
}

func generateValidResolverMD(t *testing.T, pubKey *jwktype.Jwk) *idtypes.ResolverMetadata {
	t.Helper()

	return &idtypes.ResolverMetadata{
		ID: fmt.Sprintf("DUO-%s", verificationtesting.ValidProofSub),
		VerificationMethod: []*idtypes.VerificationMethod{
			{
				ID:           pubKey.KID,
				PublicKeyJwk: pubKey,
			},
		},
	}
}

func generateValidVC(
	t *testing.T,
	idRepo idcore.IdRepository,
	issuer *issuertypes.Issuer,
) *vctypes.EnvelopedCredential {
	t.Helper()

	credential := &vctypes.VerifiableCredential{
		ID: "VC_ID",
		CredentialSubject: map[string]any{
			"id": "DUO-" + verificationtesting.ValidProofSub,
		},
	}

	privKey, pubKey, _ := genKey()
	envelope, err := signVCWithJose(credential, privKey, pubKey.KID)
	assert.NoError(t, err)

	resolverMD := generateValidResolverMD(t, pubKey)
	_, _ = idRepo.CreateID(t.Context(), resolverMD, issuer)

	return envelope
}

func signVCWithJose(
	vc *vctypes.VerifiableCredential,
	privKey any,
	kid string,
) (*vctypes.EnvelopedCredential, error) {
	payload, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}

	hdrs := jws.NewHeaders()

	err = hdrs.Set(jws.KeyIDKey, kid)
	if err != nil {
		return nil, err
	}

	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), privKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return nil, err
	}

	return &vctypes.EnvelopedCredential{
		EnvelopeType: vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE,
		Value:        string(signed),
	}, nil
}

func genKey() (*rsa.PrivateKey, *jwktype.Jwk, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	pubkey, err := jwk.PublicRawKeyOf(priv)
	if err != nil {
		return nil, nil, err
	}

	key, err := jwk.Import(pubkey)
	if err != nil {
		return nil, nil, err
	}

	err = key.Set(jwk.AlgorithmKey, jwa.RS256())
	if err != nil {
		return nil, nil, err
	}

	keyAsJson, err := json.Marshal(key)
	if err != nil {
		return nil, nil, err
	}

	var pub jwktype.Jwk

	err = json.Unmarshal(keyAsJson, &pub)
	if err != nil {
		return nil, nil, err
	}

	pub.KID = "KEY-ID"

	return priv, &pub, nil
}
