// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

/**
 * TypeScript types matching the AGNTCY Identity proto definitions.
 */

// ---- jwk.proto ----

/** JWK represents a JSON Web Key supporting RSA and post-quantum (AKP) algorithms. */
export interface Jwk {
  alg?: string;
  kty?: string;
  use?: string;
  kid?: string;
  /** Public key for AKP kty */
  pub?: string;
  /** Private key for AKP kty */
  priv?: string;
  /** Seed for ML-DSA derivation */
  seed?: string;
  // RSA fields
  e?: string;
  n?: string;
  d?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
}

/** JWKS represents a set of JSON Web Keys. */
export interface Jwks {
  keys: Jwk[];
}

// ---- errors.proto ----

export enum ErrorReason {
  UNSPECIFIED = 0,
  INTERNAL = 1,
  INVALID_CREDENTIAL_ENVELOPE_TYPE = 2,
  INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT = 3,
  INVALID_ISSUER = 4,
  ISSUER_NOT_REGISTERED = 5,
  INVALID_VERIFIABLE_CREDENTIAL = 6,
  IDP_REQUIRED = 7,
  INVALID_PROOF = 8,
  UNSUPPORTED_PROOF = 9,
  RESOLVER_METADATA_NOT_FOUND = 10,
  UNKNOWN_IDP = 11,
  ID_ALREADY_REGISTERED = 12,
  VERIFIABLE_CREDENTIAL_REVOKED = 13,
}

export interface ErrorInfo {
  reason?: ErrorReason;
  message?: string;
}

// ---- vc.proto ----

export enum CredentialContentType {
  UNSPECIFIED = 0,
  AGENT_BADGE = 1,
  MCP_BADGE = 2,
}

export enum CredentialEnvelopeType {
  UNSPECIFIED = 0,
  EMBEDDED_PROOF = 1,
  JOSE = 2,
}

export enum CredentialStatusPurpose {
  UNSPECIFIED = 0,
  REVOCATION = 1,
}

export interface BadgeClaims {
  id?: string;
  badge?: string;
}

export interface CredentialContent {
  contentType?: CredentialContentType;
  content?: Record<string, unknown>;
}

export interface CredentialSchema {
  type?: string;
  id?: string;
}

export interface CredentialStatus {
  id?: string;
  type?: string;
  createdAt?: Record<string, never>;
  purpose?: CredentialStatusPurpose;
}

export interface EnvelopedCredential {
  envelopeType?: CredentialEnvelopeType;
  value?: string;
}

export interface Proof {
  type?: string;
  proofPurpose?: string;
  proofValue?: string;
}

export interface VerifiableCredential {
  context?: string[];
  type?: string[];
  issuer?: string;
  content?: Record<string, unknown>;
  id?: string;
  issuanceDate?: string;
  expirationDate?: string;
  credentialSchema?: CredentialSchema[];
  credentialStatus?: CredentialStatus[];
  proof?: Proof;
}

export interface VerifiablePresentation {
  context?: string[];
  type?: string[];
  verifiableCredential?: VerifiableCredential[];
  proof?: Proof;
}

export interface VerificationResult {
  status?: boolean;
  document?: VerifiableCredential;
  mediaType?: string;
  controller?: string;
  controlledIdentifierDocument?: string;
  warnings?: ErrorInfo[];
  errors?: ErrorInfo[];
}

// ---- id.proto ----

export interface Service {
  serviceEndpoint?: string[];
}

export interface VerificationMethod {
  id?: string;
  publicKeyJwk?: Jwk;
}

export interface ResolverMetadata {
  id?: string;
  verificationMethod?: VerificationMethod[];
  service?: Service[];
  assertionMethod?: string[];
  controller?: string;
}

// ---- issuer.proto ----

export enum IssuerAuthType {
  UNSPECIFIED = 0,
  IDP = 1,
  SELF = 2,
}

export interface Issuer {
  organization?: string;
  subOrganization?: string;
  commonName?: string;
  verified?: boolean;
  publicKey?: Jwk;
  privateKey?: Jwk;
  authType?: IssuerAuthType;
}

// ---- mcp.proto ----

export interface McpResource {
  name?: string;
  description?: string;
  uri?: string;
}

export interface Oauth2Metadata {
  resource?: string;
  authorizationServers?: string;
  bearerMethodsSupported?: string[];
  scopesSupported?: string[];
}

export interface McpTool {
  name?: string;
  description?: string;
  parameters?: Record<string, unknown>;
  oauth2Metadata?: Oauth2Metadata;
}

export interface McpServer {
  name?: string;
  url?: string;
  tools?: McpTool[];
  resources?: McpResource[];
}

// ---- vc_service.proto (request/response) ----

export interface PublishRequest {
  vc: EnvelopedCredential;
  proof?: Proof;
}

export interface VerifyRequest {
  vc: EnvelopedCredential;
}

export interface SearchRequest {
  id: string;
  schema: CredentialSchema;
  content: string;
}

export interface SearchResponse {
  vcs: EnvelopedCredential[];
}

export interface GetVcWellKnownRequest {
  id: string;
}

export interface GetVcWellKnownResponse {
  vcs: EnvelopedCredential[];
}

export interface RevokeRequest {
  vc: EnvelopedCredential;
  proof: Proof;
}

// ---- id_service.proto (request/response) ----

export interface GenerateRequest {
  issuer: Issuer;
  proof?: Proof;
}

export interface GenerateResponse {
  resolverMetadata: ResolverMetadata;
}

export interface ResolveRequest {
  id: string;
}

export interface ResolveResponse {
  resolverMetadata: ResolverMetadata;
}

// ---- issuer_service.proto (request/response) ----

export interface RegisterIssuerRequest {
  issuer: Issuer;
  proof?: Proof;
}

export interface RegisterIssuerResponse {}

export interface GetIssuerWellKnownRequest {
  commonName: string;
}

export interface GetIssuerWellKnownResponse {
  jwks: Jwks;
}

// ---- issuer local_service.proto ----

export interface IssueVCRequest {
  id: string;
  content: CredentialContent;
  envelopeType: CredentialEnvelopeType;
}

export interface IssueVCResponse {
  vc: EnvelopedCredential;
}

export interface KeyGenResponse {
  keypair: Jwk;
}
