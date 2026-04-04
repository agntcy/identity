import { describe, it, expect } from "vitest";
import {
  CredentialEnvelopeType,
  CredentialContentType,
  CredentialStatusPurpose,
  ErrorReason,
  IssuerAuthType,
  type EnvelopedCredential,
  type Proof,
  type VerifiableCredential,
  type VerificationResult,
  type ResolverMetadata,
  type Issuer,
  type Jwk,
  type Jwks,
  type McpServer,
  type SearchRequest,
  type CredentialSchema,
  type BadgeClaims,
} from "../index.js";

describe("Type construction", () => {
  it("should construct EnvelopedCredential", () => {
    const ec: EnvelopedCredential = {
      envelopeType: CredentialEnvelopeType.JOSE,
      value: "eyJhbGciOiJSUzI1NiJ9...",
    };
    expect(ec.envelopeType).toBe(CredentialEnvelopeType.JOSE);
    expect(ec.value).toBeDefined();
  });

  it("should construct Proof", () => {
    const proof: Proof = {
      type: "DataIntegrityProof",
      proofPurpose: "assertionMethod",
      proofValue: "z3FXQjecWufY46...",
    };
    expect(proof.type).toBe("DataIntegrityProof");
  });

  it("should construct VerifiableCredential", () => {
    const vc: VerifiableCredential = {
      context: ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      issuer: "did:example:123",
      id: "urn:uuid:abc",
      issuanceDate: "2025-01-01T00:00:00Z",
      credentialSchema: [{ type: "JsonSchema", id: "https://example.com/schema" }],
      credentialStatus: [],
    };
    expect(vc.context).toHaveLength(1);
    expect(vc.issuer).toBe("did:example:123");
  });

  it("should construct VerificationResult", () => {
    const result: VerificationResult = {
      status: true,
      mediaType: "application/vc",
      warnings: [],
      errors: [],
    };
    expect(result.status).toBe(true);
  });

  it("should construct ResolverMetadata", () => {
    const rm: ResolverMetadata = {
      id: "did:example:456",
      verificationMethod: [{ id: "#key-1", publicKeyJwk: { kty: "RSA", alg: "RS256" } }],
      service: [{ serviceEndpoint: ["https://example.com"] }],
      assertionMethod: ["#key-1"],
      controller: "did:example:456",
    };
    expect(rm.verificationMethod).toHaveLength(1);
  });

  it("should construct Issuer", () => {
    const issuer: Issuer = {
      organization: "ACME",
      commonName: "acme.example.com",
      authType: IssuerAuthType.SELF,
    };
    expect(issuer.authType).toBe(IssuerAuthType.SELF);
  });

  it("should construct Jwk and Jwks", () => {
    const jwk: Jwk = { kty: "AKP", alg: "ML-DSA-65", pub: "abc123" };
    const jwks: Jwks = { keys: [jwk] };
    expect(jwks.keys).toHaveLength(1);
  });

  it("should construct McpServer", () => {
    const server: McpServer = {
      name: "test-server",
      url: "https://mcp.example.com",
      tools: [{ name: "search", description: "Search tool" }],
      resources: [{ name: "db", uri: "postgres://..." }],
    };
    expect(server.tools).toHaveLength(1);
  });

  it("should construct SearchRequest", () => {
    const req: SearchRequest = {
      id: "did:example:789",
      schema: { type: "JsonSchema", id: "https://example.com/schema" },
      content: '{"name":"test"}',
    };
    expect(req.id).toBe("did:example:789");
  });

  it("should have correct enum values", () => {
    expect(CredentialContentType.AGENT_BADGE).toBe(1);
    expect(CredentialContentType.MCP_BADGE).toBe(2);
    expect(CredentialStatusPurpose.REVOCATION).toBe(1);
    expect(ErrorReason.INVALID_PROOF).toBe(8);
    expect(ErrorReason.VERIFIABLE_CREDENTIAL_REVOKED).toBe(13);
  });
});
