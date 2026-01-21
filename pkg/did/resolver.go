// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package did

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const Resolver_Timeout = 30

// UniversalResolverConfig contains configuration for the Universal Resolver client
type UniversalResolverConfig struct {
	// BaseURL is the base URL of the Universal Resolver endpoint
	// Default: https://dev.uniresolver.io
	BaseURL string

	// Timeout for HTTP requests
	Timeout time.Duration

	// HTTPClient allows using a custom HTTP client
	HTTPClient *http.Client
}

// Resolver provides DID resolution capabilities using Universal Resolver
type Resolver struct {
	config     UniversalResolverConfig
	httpClient *http.Client
}

// DIDResolutionResult represents the complete result from DID resolution
// as defined in W3C DID Resolution specification
type DIDResolutionResult struct {
	// The resolution context
	Context string `json:"@context,omitempty"`

	// The DID Document
	DIDDocument *DIDDocument `json:"didDocument,omitempty"`

	// Metadata about the DID resolution process
	DIDResolutionMetadata *DIDResolutionMetadata `json:"didResolutionMetadata,omitempty"`

	// Metadata about the DID Document
	DIDDocumentMetadata *DIDDocumentMetadata `json:"didDocumentMetadata,omitempty"`
}

// DIDDocument represents a W3C DID Document
type DIDDocument struct {
	// The DID as defined in the document
	ID string `json:"id"`

	// A list of contexts
	Context []interface{} `json:"@context,omitempty"`

	// Also known as
	AlsoKnownAs []string `json:"alsoKnownAs,omitempty"`

	// Controller(s) of the DID
	Controller interface{} `json:"controller,omitempty"`

	// Verification methods (public keys)
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`

	// Authentication verification methods
	Authentication []interface{} `json:"authentication,omitempty"`

	// Assertion method verification methods
	AssertionMethod []interface{} `json:"assertionMethod,omitempty"`

	// Key agreement verification methods
	KeyAgreement []interface{} `json:"keyAgreement,omitempty"`

	// Capability invocation verification methods
	CapabilityInvocation []interface{} `json:"capabilityInvocation,omitempty"`

	// Capability delegation verification methods
	CapabilityDelegation []interface{} `json:"capabilityDelegation,omitempty"`

	// Service endpoints
	Service []Service `json:"service,omitempty"`
}

// VerificationMethod represents a verification method in a DID Document
type VerificationMethod struct {
	// The verification method ID
	ID string `json:"id"`

	// The type of verification method
	Type string `json:"type"`

	// The controller of this verification method
	Controller string `json:"controller"`

	// Public key in JWK format
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk,omitempty"`

	// Public key in Multibase format
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`

	// Public key in Base58 format
	PublicKeyBase58 string `json:"publicKeyBase58,omitempty"`
}

// Service represents a service endpoint in a DID Document
type Service struct {
	// The service ID
	ID string `json:"id"`

	// The service type
	Type interface{} `json:"type"`

	// The service endpoint
	ServiceEndpoint interface{} `json:"serviceEndpoint"`

	// Additional properties
	Description string `json:"description,omitempty"`
}

// DIDResolutionMetadata contains metadata about the resolution process
type DIDResolutionMetadata struct {
	// Content type of the DID Document
	ContentType string `json:"contentType,omitempty"`

	// Error code if resolution failed
	Error string `json:"error,omitempty"`

	// Additional properties
	Duration int64 `json:"duration,omitempty"`

	// DID URL dereferencing metadata
	DidUrl *DIDURLMetadata `json:"didUrl,omitempty"`
}

// DIDDocumentMetadata contains metadata about the DID Document
type DIDDocumentMetadata struct {
	// When the DID was created
	Created string `json:"created,omitempty"`

	// When the DID was last updated
	Updated string `json:"updated,omitempty"`

	// Whether the DID is deactivated
	Deactivated bool `json:"deactivated,omitempty"`

	// Version ID
	VersionId string `json:"versionId,omitempty"`

	// Next version ID
	NextVersionId string `json:"nextVersionId,omitempty"`

	// Next update time
	NextUpdate string `json:"nextUpdate,omitempty"`

	// Equivalent IDs
	EquivalentId []string `json:"equivalentId,omitempty"`

	// Canonical ID
	CanonicalId string `json:"canonicalId,omitempty"`

	// Method-specific metadata
	Method map[string]interface{} `json:"method,omitempty"`
}

// DIDURLMetadata contains metadata for DID URL dereferencing
type DIDURLMetadata struct {
	// The DID URL being dereferenced
	DidUrl string `json:"didUrl,omitempty"`

	// Content type
	ContentType string `json:"contentType,omitempty"`
}

// ResolveOptions contains options for DID resolution
type ResolveOptions struct {
	// Accept header for content negotiation
	// Examples: "application/did+ld+json", "application/did+json"
	Accept string

	// Additional query parameters
	QueryParams map[string]string
}

// NewResolver creates a new DID Resolver client
func NewResolver(config UniversalResolverConfig) *Resolver {
	if config.BaseURL == "" {
		config.BaseURL = "https://dev.uniresolver.io"
	}

	if config.Timeout == 0 {
		config.Timeout = Resolver_Timeout * time.Second
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.Timeout,
		}
	}

	return &Resolver{
		config:     config,
		httpClient: httpClient,
	}
}

// Resolve resolves a DID to its DID Document and metadata
func (r *Resolver) Resolve(ctx context.Context, did string, opts *ResolveOptions) (*DIDResolutionResult, error) {
	if did == "" {
		return nil, fmt.Errorf("DID cannot be empty")
	}

	// Construct URL
	url := fmt.Sprintf("%s/1.0/identifiers/%s", r.config.BaseURL, did)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set default accept header for full resolution result
	acceptHeader := "application/ld+json;profile=\"https://w3id.org/did-resolution\""
	if opts != nil && opts.Accept != "" {
		acceptHeader = opts.Accept
	}

	req.Header.Set("Accept", acceptHeader)

	// Add query parameters if provided
	if opts != nil && len(opts.QueryParams) > 0 {
		q := req.URL.Query()
		for key, value := range opts.QueryParams {
			q.Add(key, value)
		}

		req.URL.RawQuery = q.Encode()
	}

	// Execute request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle HTTP errors
	if resp.StatusCode != http.StatusOK {
		// Even on error, try to parse the response as it may contain error details
		var result DIDResolutionResult
		if err := json.Unmarshal(body, &result); err == nil {
			return &result, fmt.Errorf(
				"resolution failed with status %d: %s",
				resp.StatusCode,
				result.DIDResolutionMetadata.Error,
			)
		}

		return nil, fmt.Errorf("resolution failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result DIDResolutionResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse resolution result: %w", err)
	}

	return &result, nil
}

// ResolveDIDDocument is a convenience method that only returns the DID Document
func (r *Resolver) ResolveDIDDocument(ctx context.Context, did string) (*DIDDocument, error) {
	opts := &ResolveOptions{
		Accept: "application/did+ld+json",
	}

	result, err := r.Resolve(ctx, did, opts)
	if err != nil {
		return nil, err
	}

	if result.DIDDocument == nil {
		return nil, fmt.Errorf("DID document not found in resolution result")
	}

	return result.DIDDocument, nil
}

// DereferenceResource dereferences a DID URL to retrieve a specific resource
// Example: did:cheqd:testnet:abc123/resources/xyz456
func (r *Resolver) DereferenceResource(
	ctx context.Context,
	didURL string,
	opts *ResolveOptions,
) (*DIDResolutionResult, error) {
	if didURL == "" {
		return nil, fmt.Errorf("DID URL cannot be empty")
	}

	// Use the same resolution endpoint - Universal Resolver handles DID URL dereferencing
	return r.Resolve(ctx, didURL, opts)
}

// GetSupportedMethods retrieves the list of DID methods supported by the resolver
func (r *Resolver) GetSupportedMethods(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/1.0/methods", r.config.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	var methods []string
	if err := json.NewDecoder(resp.Body).Decode(&methods); err != nil {
		return nil, fmt.Errorf("failed to parse methods: %w", err)
	}

	return methods, nil
}

// GetProperties retrieves the properties/configuration of the resolver
func (r *Resolver) GetProperties(ctx context.Context) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/1.0/properties", r.config.BaseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d", resp.StatusCode)
	}

	var properties map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&properties); err != nil {
		return nil, fmt.Errorf("failed to parse properties: %w", err)
	}

	return properties, nil
}

// VerifyDIDOwnership verifies that a signature was created by the controller of a DID
// This is a helper function that resolves the DID and checks verification methods
func (r *Resolver) VerifyDIDOwnership(
	ctx context.Context,
	did, verificationMethodId string,
) (*VerificationMethod, error) {
	result, err := r.Resolve(ctx, did, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DID: %w", err)
	}

	if result.DIDDocument == nil {
		return nil, fmt.Errorf("DID document not found")
	}

	// Check if DID is deactivated
	if result.DIDDocumentMetadata != nil && result.DIDDocumentMetadata.Deactivated {
		return nil, fmt.Errorf("DID is deactivated")
	}

	// Find the verification method
	for _, vm := range result.DIDDocument.VerificationMethod {
		if vm.ID == verificationMethodId {
			return &vm, nil
		}
	}

	return nil, fmt.Errorf("verification method %s not found in DID document", verificationMethodId)
}
