// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package node

import (
	"context"
	"fmt"

	"github.com/agntcy/identity/internal/core/id/types"
	"github.com/agntcy/identity/pkg/did"
	"github.com/agntcy/identity/pkg/jwk"
)

const (
	KeyTypeEd25519        = "Ed25519"
	KeyTypeX25519         = "X25519"
	KeyTypeSecp256k1      = "Secp256k1"
	KeyTypeEcdsaSecp256k1 = "EcdsaSecp256k1"
	KeyTypeP256           = "P256"
	KeyTypePrime256       = "Prime256"
	KeyTypeP384           = "P384"
	KeyTypeP521           = "P521"
	KeyTypeOKP            = "OKP"
	KeyTypeEC             = "EC"
	CurveEd25519          = "Ed25519"
	CurveX25519           = "X25519"
	CurveSecp256k1        = "secp256k1"
	CurveP256             = "P-256"
	CurveP384             = "P-384"
	CurveP521             = "P-521"
)

type DIDService interface {
	// Create a new DID on Cheqd using an existing public key
	CreateDID(
		ctx context.Context,
		publicKey *jwk.Jwk,
		organization string,
	) (didID string, didDocument *did.DIDDocument, err error)
}

type didService struct {
	registrar *did.Registrar
	network   string
}

func NewDIDService(registrarURL, network string) DIDService {
	return &didService{
		registrar: did.NewRegistrar(did.UniversalRegistrarConfig{BaseURL: registrarURL}),
		network:   network,
	}
}

func (s *didService) CreateDID(
	ctx context.Context,
	publicKey *jwk.Jwk,
	organization string,
) (string, *did.DIDDocument, error) {
	// Note: User must have BOTH public and private keys
	// They generated the keypair via KeyGen
	// They keep the private key client-side
	// We only use the public key to create the DID

	// Step 1: Initiate DID creation
	didPayload, err := s.registrar.GetDIDDocument(ctx, &did.CreateOptions{
		VerificationMethodType: "Ed25519VerificationKey2020",
		Network:                s.network,
	})
	if err != nil {
		return "", nil, fmt.Errorf("DID creation failed: %w", err)
	}

	createReq := &did.CreateDIDRequest{
		DIDDocument: didPayload,
		Options: &did.CreateOptions{
			Network: s.network,
		},
	}

	createResp, err := s.registrar.Create(ctx, createReq)
	if err != nil {
		return "", nil, fmt.Errorf("DID creation failed: %w", err)
	}

	// Step 2: Check if signing is required
	if !createResp.IsFinished() && createResp.IsActionRequired() {
		return "", nil, fmt.Errorf(
			"DID creation requires signing, but user must sign client-side. "+
				"Payload to sign: %s", createResp.GetSerializedPayload())
	}

	// Verify success
	if !createResp.IsFinished() {
		return "", nil, fmt.Errorf("DID creation incomplete")
	}

	didID := createResp.DIDState.DID
	didDocument := createResp.DIDState.DIDDocument

	return didID, didDocument, nil
}

// ConvertDIDDocToResolverMetadata converts a DID Document to agntcy ResolverMetadata
// This is used when registering a DID-based issuer
func ConvertDIDDocToResolverMetadata(
	didDoc *did.DIDDocument,
	didID string,
) (*types.ResolverMetadata, error) {
	if didDoc == nil {
		return nil, fmt.Errorf("DID document is nil")
	}

	resolverMetadata := &types.ResolverMetadata{
		Controller: extractController(didDoc),
	}

	// Convert verification methods
	verificationMethods := make([]*types.VerificationMethod, 0, len(didDoc.VerificationMethod))
	assertionMethods := make([]string, 0)

	for _, vm := range didDoc.VerificationMethod {
		// Convert to agntcy VerificationMethod
		agntcyVM, err := convertVerificationMethod(&vm)
		if err != nil {
			continue // Skip invalid verification methods
		}

		verificationMethods = append(verificationMethods, agntcyVM)

		// Check if this VM is used for assertion (signing credentials)
		if isAssertionMethod(vm.ID, didDoc.AssertionMethod) {
			// Use the agntcy-style ID reference
			assertionMethods = append(assertionMethods, agntcyVM.ID)
		}
	}

	resolverMetadata.VerificationMethod = verificationMethods
	resolverMetadata.AssertionMethod = assertionMethods

	// Convert services
	services := make([]*types.Service, 0, len(didDoc.Service))
	for _, svc := range didDoc.Service {
		agntcySvc := convertService(svc)
		if agntcySvc != nil {
			services = append(services, agntcySvc)
		}
	}

	resolverMetadata.Service = services

	return resolverMetadata, nil
}

// convertVerificationMethod converts a DID VerificationMethod to agntcy VerificationMethod
func convertVerificationMethod(
	vm *did.VerificationMethod,
) (*types.VerificationMethod, error) {
	// Convert public key to JWK
	publicKey, err := verificationMethodToJWK(vm)
	if err != nil {
		return nil, err
	}

	return &types.VerificationMethod{
		ID:           vm.ID,
		PublicKeyJwk: publicKey,
	}, nil
}

// convertService converts a DID Service to agntcy Service
func convertService(svc did.Service) *types.Service {
	// Extract service endpoints
	endpoints := make([]string, 0)

	switch ep := svc.ServiceEndpoint.(type) {
	case string:
		endpoints = append(endpoints, ep)
	case []interface{}:
		for _, e := range ep {
			if str, ok := e.(string); ok {
				endpoints = append(endpoints, str)
			}
		}
	case []string:
		endpoints = ep
	}

	if len(endpoints) == 0 {
		return nil // Skip services with no endpoints
	}

	return &types.Service{
		ServiceEndpoint: endpoints,
	}
}

// verificationMethodToJWK converts a DID VerificationMethod to JWK
func verificationMethodToJWK(vm *did.VerificationMethod) (*jwk.Jwk, error) {
	// If already in JWK format
	if len(vm.PublicKeyJwk) > 0 {
		return extractJWKFromPublicKeyJwk(vm)
	}

	// Handle multibase format
	if vm.PublicKeyMultibase != "" {
		kty := keyTypeFromVerificationMethodType(vm.Type)

		return &jwk.Jwk{
			KID: vm.ID,
			KTY: kty,
			USE: "sig",
			PUB: vm.PublicKeyMultibase,
		}, nil
	}

	// Handle Base58 format (legacy)
	if vm.PublicKeyBase58 != "" {
		kty := keyTypeFromVerificationMethodType(vm.Type)

		return &jwk.Jwk{
			KID: vm.ID,
			KTY: kty,
			USE: "sig",
			PUB: vm.PublicKeyBase58,
		}, nil
	}

	return nil, fmt.Errorf("unsupported key format in verification method")
}

// extractJWKFromPublicKeyJwk extracts JWK data from PublicKeyJwk field
func extractJWKFromPublicKeyJwk(vm *did.VerificationMethod) (*jwk.Jwk, error) {
	jwkData := &jwk.Jwk{
		KID: vm.ID,
		USE: "sig",
	}

	// Extract JWK fields from the map
	if kty, ok := vm.PublicKeyJwk["kty"].(string); ok {
		jwkData.KTY = kty
	}

	if x, ok := vm.PublicKeyJwk["x"].(string); ok {
		jwkData.PUB = x
	}

	if alg, ok := vm.PublicKeyJwk["alg"].(string); ok {
		jwkData.ALG = alg
	}

	// Infer key type from curve if not already set
	if jwkData.KTY == "" {
		if crv, ok := vm.PublicKeyJwk["crv"].(string); ok {
			if crv == CurveEd25519 || crv == CurveX25519 {
				jwkData.KTY = KeyTypeOKP
			} else {
				jwkData.KTY = KeyTypeEC
			}
		}
	}

	return jwkData, nil
}

// keyTypeFromVerificationMethodType determines JWK key type from verification method type
func keyTypeFromVerificationMethodType(vmType string) string {
	switch {
	case contains(vmType, KeyTypeEd25519):
		return KeyTypeOKP
	case contains(vmType, KeyTypeX25519):
		return KeyTypeOKP
	case contains(vmType, KeyTypeSecp256k1), contains(vmType, KeyTypeEcdsaSecp256k1):
		return KeyTypeEC
	case contains(vmType, KeyTypeP256), contains(vmType, KeyTypePrime256):
		return KeyTypeEC
	case contains(vmType, KeyTypeP384):
		return KeyTypeEC
	case contains(vmType, KeyTypeP521):
		return KeyTypeEC
	default:
		return KeyTypeOKP // Safe default
	}
}

// extractController extracts the controller from a DID Document
func extractController(didDoc *did.DIDDocument) string {
	if didDoc.Controller == nil {
		return didDoc.ID // Use the DID itself as controller
	}

	switch ctrl := didDoc.Controller.(type) {
	case string:
		return ctrl
	case []interface{}:
		if len(ctrl) > 0 {
			if str, ok := ctrl[0].(string); ok {
				return str
			}
		}
	case []string:
		if len(ctrl) > 0 {
			return ctrl[0]
		}
	}

	return didDoc.ID // Fallback to DID itself
}

// isAssertionMethod checks if a verification method ID is in the assertionMethod array
func isAssertionMethod(vmID string, assertionMethods interface{}) bool {
	if assertionMethods == nil {
		return false
	}

	switch am := assertionMethods.(type) {
	case []interface{}:
		for _, method := range am {
			switch m := method.(type) {
			case string:
				if m == vmID {
					return true
				}
			case map[string]interface{}:
				// Embedded verification method
				if id, ok := m["id"].(string); ok && id == vmID {
					return true
				}
			}
		}
	case []string:
		for _, m := range am {
			if m == vmID {
				return true
			}
		}
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive helper)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			indexOf(s, substr) >= 0)))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}

	return -1
}
