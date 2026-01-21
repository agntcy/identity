// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package did

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const Registrar_Timeout = 60

// UniversalRegistrarConfig contains configuration for the Universal Registrar client
type UniversalRegistrarConfig struct {
	// BaseURL is the base URL of the Universal Registrar endpoint
	// Default: https://did-registrar.cheqd.net for cheqd-specific registrar
	BaseURL string

	// Timeout for HTTP requests
	Timeout time.Duration

	// HTTPClient allows using a custom HTTP client
	HTTPClient *http.Client
}

// Registrar provides DID registration capabilities using Universal Registrar
type Registrar struct {
	config     UniversalRegistrarConfig
	httpClient *http.Client
}

// CreateDIDRequest represents a request to create a new DID
type CreateDIDRequest struct {
	// The DID Document to be created (optional for some methods)
	DIDDocument *DIDDocument `json:"didDocument,omitempty"`

	// Options specific to the DID method
	Options *CreateOptions `json:"options,omitempty"`

	// Secret data required for DID creation (e.g., keys, passwords)
	Secret *CreateSecret `json:"secret,omitempty"`

	// Job ID for continuing a multi-step operation
	JobID string `json:"jobId,omitempty"`
}

// CreateOptions contains method-specific options for DID creation
type CreateOptions struct {
	// Network to create the DID on (e.g., "testnet", "mainnet")
	Network string `json:"network,omitempty"`

	// Verification method type (e.g., "Ed25519VerificationKey2020", "JsonWebKey2020")
	VerificationMethodType string `json:"verificationMethodType,omitempty"`

	// Method-specific algorithm (e.g., "Ed25519", "ES256K")
	MethodSpecificIdAlgo string `json:"methodSpecificIdAlgo,omitempty"`

	// Public key multibase for key generation
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`

	// Public key hex for key generation
	PublicKeyHex string `json:"publicKeyHex,omitempty"`

	// Additional method-specific options
	Additional map[string]interface{} `json:"-"`
}

// CreateSecret contains secret data for DID creation
type CreateSecret struct {
	// Signing responses for multi-step operations
	SigningResponse *SigningResponse `json:"signingResponse,omitempty"`

	// Token/API key for authenticated operations
	Token string `json:"token,omitempty"`

	// Additional secret data
	Additional map[string]interface{} `json:"-"`
}

// SigningResponse contains signature(s) for multi-step DID operations
type SigningResponse struct {
	// Verification method ID that created the signature
	VerificationMethodID string `json:"verificationMethodId,omitempty"`

	// The signature value
	Signature string `json:"signature,omitempty"`

	// Multiple signatures (for controllers with multiple verification methods)
	Signatures []Signature `json:"signatures,omitempty"`
}

// Signature represents a single signature
type Signature struct {
	// Verification method ID that created this signature
	VerificationMethodID string `json:"verificationMethodId"`

	// The signature value
	Signature string `json:"signature"`
}

// CreateDIDResponse represents the response from a DID creation request
type CreateDIDResponse struct {
	// Job ID for multi-step operations
	JobID string `json:"jobId,omitempty"`

	// The state of the DID creation process
	DIDState *DIDState `json:"didState,omitempty"`

	// Metadata about the registration process
	DIDRegistrationMetadata *DIDRegistrationMetadata `json:"didRegistrationMetadata,omitempty"`

	// Metadata about the DID Document
	DIDDocumentMetadata *DIDDocumentMetadata `json:"didDocumentMetadata,omitempty"`
}

// DIDState represents the state of a DID during the registration process
type DIDState struct {
	// The state: "action", "finished", "failed"
	State string `json:"state"`

	// The DID identifier (when finished)
	DID string `json:"did,omitempty"`

	// The DID Document (when finished)
	DIDDocument *DIDDocument `json:"didDocument,omitempty"`

	// The secret data (when state is "action")
	Secret *StateSecret `json:"secret,omitempty"`

	// Action required (when state is "action")
	Action string `json:"action,omitempty"`

	// Description of the required action
	Description string `json:"description,omitempty"`

	// Wait time in seconds before next action
	Wait int `json:"wait,omitempty"`

	// Error reason (when state is "failed")
	Reason string `json:"reason,omitempty"`
}

// StateSecret contains secret data returned in a DID state requiring action
type StateSecret struct {
	// Serialized payload to be signed
	SerializedPayload string `json:"serializedPayload,omitempty"`

	// Verification method ID that should sign
	VerificationMethodID []string `json:"verificationMethodId,omitempty"`

	// Additional secret data
	Additional map[string]interface{} `json:"-"`
}

// DIDRegistrationMetadata contains metadata about the registration process
type DIDRegistrationMetadata struct {
	// Duration of the operation in milliseconds
	Duration int64 `json:"duration,omitempty"`

	// Method-specific metadata
	Method map[string]interface{} `json:"method,omitempty"`

	// Content type
	ContentType string `json:"contentType,omitempty"`
}

// UpdateDIDRequest represents a request to update an existing DID
type UpdateDIDRequest struct {
	// The DID to update
	DID string `json:"did,omitempty"`

	// The updated DID Document
	DIDDocument *DIDDocument `json:"didDocument,omitempty"`

	// Options for the update operation
	Options *UpdateOptions `json:"options,omitempty"`

	// Secret data for the update
	Secret *UpdateSecret `json:"secret,omitempty"`

	// Job ID for continuing a multi-step operation
	JobID string `json:"jobId,omitempty"`
}

// UpdateOptions contains options for DID update operations
type UpdateOptions struct {
	// Network the DID exists on
	Network string `json:"network,omitempty"`

	// Additional method-specific options
	Additional map[string]interface{} `json:"-"`
}

// UpdateSecret contains secret data for DID updates
type UpdateSecret struct {
	// Signing responses for multi-step operations
	SigningResponse *SigningResponse `json:"signingResponse,omitempty"`

	// Additional secret data
	Additional map[string]interface{} `json:"-"`
}

// DeactivateDIDRequest represents a request to deactivate a DID
type DeactivateDIDRequest struct {
	// The DID to deactivate
	DID string `json:"did,omitempty"`

	// Options for the deactivation
	Options *DeactivateOptions `json:"options,omitempty"`

	// Secret data for deactivation
	Secret *DeactivateSecret `json:"secret,omitempty"`

	// Job ID for continuing a multi-step operation
	JobID string `json:"jobId,omitempty"`
}

// DeactivateOptions contains options for DID deactivation
type DeactivateOptions struct {
	// Network the DID exists on
	Network string `json:"network,omitempty"`

	// Additional method-specific options
	Additional map[string]interface{} `json:"-"`
}

// DeactivateSecret contains secret data for DID deactivation
type DeactivateSecret struct {
	// Signing responses for multi-step operations
	SigningResponse *SigningResponse `json:"signingResponse,omitempty"`

	// Additional secret data
	Additional map[string]interface{} `json:"-"`
}

// CreateResourceRequest represents a request to create a DID-Linked Resource (cheqd-specific)
type CreateResourceRequest struct {
	// The DID that will control the resource
	DID string `json:"did,omitempty"`

	// The resource data
	Data []byte `json:"data,omitempty"`

	// Resource metadata
	Name        string                   `json:"name,omitempty"`
	Type        string                   `json:"type,omitempty"`
	Version     string                   `json:"version,omitempty"`
	AlsoKnownAs []ResourceAlternativeURI `json:"alsoKnownAs,omitempty"`

	// Options for resource creation
	Options *ResourceOptions `json:"options,omitempty"`

	// Secret data for resource creation
	Secret *ResourceSecret `json:"secret,omitempty"`

	// Job ID for continuing a multi-step operation
	JobID string `json:"jobId,omitempty"`
}

// ResourceAlternativeURI represents alternative URIs for a resource
type ResourceAlternativeURI struct {
	URI         string `json:"uri"`
	Description string `json:"description,omitempty"`
}

// ResourceOptions contains options for resource operations
type ResourceOptions struct {
	// Network to create the resource on
	Network string `json:"network,omitempty"`

	// Additional options
	Additional map[string]interface{} `json:"-"`
}

// ResourceSecret contains secret data for resource operations
type ResourceSecret struct {
	// Signing responses
	SigningResponse *SigningResponse `json:"signingResponse,omitempty"`

	// Additional secret data
	Additional map[string]interface{} `json:"-"`
}

// NewRegistrar creates a new DID Registrar client
func NewRegistrar(config UniversalRegistrarConfig) *Registrar {
	if config.BaseURL == "" {
		// Default to cheqd's registrar - can be changed for other methods
		config.BaseURL = "https://did-registrar.cheqd.net"
	}

	if config.Timeout == 0 {
		config.Timeout = Registrar_Timeout * time.Second
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.Timeout,
		}
	}

	return &Registrar{
		config:     config,
		httpClient: httpClient,
	}
}

// Create creates a new DID
func (r *Registrar) Create(ctx context.Context, req *CreateDIDRequest) (*CreateDIDResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	return r.doRegistrarRequest(ctx, "/create", req)
}

// Update updates an existing DID
func (r *Registrar) Update(ctx context.Context, req *UpdateDIDRequest) (*CreateDIDResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.DID == "" {
		return nil, fmt.Errorf("DID is required for update")
	}

	return r.doRegistrarRequest(ctx, "/update", req)
}

// Deactivate deactivates a DID
func (r *Registrar) Deactivate(ctx context.Context, req *DeactivateDIDRequest) (*CreateDIDResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.DID == "" {
		return nil, fmt.Errorf("DID is required for deactivation")
	}

	return r.doRegistrarRequest(ctx, "/deactivate", req)
}

// CreateResource creates a DID-Linked Resource (cheqd-specific feature)
func (r *Registrar) CreateResource(ctx context.Context, req *CreateResourceRequest) (*CreateDIDResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.DID == "" {
		return nil, fmt.Errorf("DID is required for resource creation")
	}

	// cheqd registrar supports both /createResource and /{did}/create-resource
	return r.doRegistrarRequest(ctx, "/createResource", req)
}

// GetDIDDocument is a helper endpoint to generate a DID document template (cheqd-specific)
func (r *Registrar) GetDIDDocument(ctx context.Context, opts *CreateOptions) (*DIDDocument, error) {
	url := fmt.Sprintf("%s/did-document", r.config.BaseURL)

	// Build query parameters
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if opts != nil {
		q := req.URL.Query()
		if opts.VerificationMethodType != "" {
			q.Add("verificationMethodType", opts.VerificationMethodType)
		}

		if opts.MethodSpecificIdAlgo != "" {
			q.Add("methodSpecificIdAlgo", opts.MethodSpecificIdAlgo)
		}

		if opts.Network != "" {
			q.Add("network", opts.Network)
		}

		if opts.PublicKeyHex != "" {
			q.Add("publicKeyHex", opts.PublicKeyHex)
		}

		req.URL.RawQuery = q.Encode()
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		DIDDoc *DIDDocument `json:"didDoc"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result.DIDDoc, nil
}

// GetSupportedMethods retrieves the list of DID methods supported by the registrar
func (r *Registrar) GetSupportedMethods(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/methods", r.config.BaseURL)

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

// GetProperties retrieves the properties/configuration of the registrar
func (r *Registrar) GetProperties(ctx context.Context) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/properties", r.config.BaseURL)

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

// doRegistrarRequest is a helper method to perform registrar API requests
func (r *Registrar) doRegistrarRequest(ctx context.Context, endpoint string, payload any) (*CreateDIDResponse, error) {
	url := fmt.Sprintf("%s%s", r.config.BaseURL, endpoint)

	// Marshal payload
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response
	var result CreateDIDResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response (status %d): %w, body: %s", resp.StatusCode, err, string(respBody))
	}

	// Check for errors in the response
	if result.DIDState != nil && result.DIDState.State == "failed" {
		return &result, fmt.Errorf("operation failed: %s", result.DIDState.Reason)
	}

	return &result, nil
}

// IsActionRequired checks if the registration response requires further action
func (r *CreateDIDResponse) IsActionRequired() bool {
	return r.DIDState != nil && r.DIDState.State == "action"
}

// IsFinished checks if the registration is complete
func (r *CreateDIDResponse) IsFinished() bool {
	return r.DIDState != nil && r.DIDState.State == "finished"
}

// IsFailed checks if the registration failed
func (r *CreateDIDResponse) IsFailed() bool {
	return r.DIDState != nil && r.DIDState.State == "failed"
}

// GetSerializedPayload extracts the serialized payload that needs to be signed
func (r *CreateDIDResponse) GetSerializedPayload() string {
	if r.DIDState != nil && r.DIDState.Secret != nil {
		return r.DIDState.Secret.SerializedPayload
	}

	return ""
}

// GetVerificationMethodIDs extracts the verification method IDs that need to sign
func (r *CreateDIDResponse) GetVerificationMethodIDs() []string {
	if r.DIDState != nil && r.DIDState.Secret != nil {
		return r.DIDState.Secret.VerificationMethodID
	}

	return nil
}
