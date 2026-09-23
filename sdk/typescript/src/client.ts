// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

import type {
  EnvelopedCredential,
  Proof,
  VerificationResult,
  SearchRequest,
  SearchResponse,
  GetVcWellKnownResponse,
  GenerateRequest,
  GenerateResponse,
  ResolveRequest,
  ResolveResponse,
  RegisterIssuerRequest,
  RegisterIssuerResponse,
  GetIssuerWellKnownResponse,
  Issuer,
  CredentialSchema,
} from "./types.js";

/** Error thrown by the Identity SDK on HTTP failures. */
export class IdentityApiError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly body: unknown,
  ) {
    super(`Identity API error ${statusCode}: ${JSON.stringify(body)}`);
    this.name = "IdentityApiError";
  }
}

export interface IdentitySdkOptions {
  /** Base URL of the Identity HTTP/JSON gateway (no trailing slash). */
  baseUrl: string;
  /** Optional custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof globalThis.fetch;
  /** Optional headers added to every request. */
  headers?: Record<string, string>;
}

/**
 * TypeScript SDK client for the AGNTCY Identity service.
 *
 * Communicates with the HTTP/JSON gateway (gRPC-Gateway).
 */
export class IdentitySdk {
  private readonly baseUrl: string;
  private readonly fetch: typeof globalThis.fetch;
  private readonly headers: Record<string, string>;

  constructor(options: IdentitySdkOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetch = options.fetch ?? globalThis.fetch;
    this.headers = {
      "Content-Type": "application/json",
      ...options.headers,
    };
  }

  // ---------- VC Service ----------

  /**
   * Get well-known Verifiable Credentials for an ID.
   * GET /v1alpha1/vc/{id}/.well-known/vcs.json
   */
  async getBadge(badgeId: string): Promise<EnvelopedCredential> {
    const res = await this.get<GetVcWellKnownResponse>(
      `/v1alpha1/vc/${encodeURIComponent(badgeId)}/.well-known/vcs.json`,
    );
    if (!res.vcs || res.vcs.length === 0) {
      throw new Error(`No badge found for ID: ${badgeId}`);
    }
    return res.vcs[0];
  }

  /**
   * Get all well-known Verifiable Credentials for an ID.
   * GET /v1alpha1/vc/{id}/.well-known/vcs.json
   */
  async getWellKnownVcs(badgeId: string): Promise<GetVcWellKnownResponse> {
    return this.get<GetVcWellKnownResponse>(
      `/v1alpha1/vc/${encodeURIComponent(badgeId)}/.well-known/vcs.json`,
    );
  }

  /**
   * Verify a Verifiable Credential.
   * POST /v1alpha1/vc/verify
   */
  async verifyBadge(badge: EnvelopedCredential): Promise<VerificationResult> {
    return this.post<VerificationResult>("/v1alpha1/vc/verify", { vc: badge });
  }

  /**
   * Publish a Verifiable Credential.
   * POST /v1alpha1/vc/publish
   */
  async publish(vc: EnvelopedCredential, proof?: Proof): Promise<void> {
    await this.post("/v1alpha1/vc/publish", { vc, proof });
  }

  /**
   * Search for Verifiable Credentials.
   * POST /v1alpha1/vc/search
   */
  async search(criteria: SearchRequest): Promise<SearchResponse> {
    return this.post<SearchResponse>("/v1alpha1/vc/search", criteria);
  }

  /**
   * Revoke a Verifiable Credential. THIS ACTION IS NOT REVERSIBLE.
   * POST /v1alpha1/vc/revoke
   */
  async revoke(vc: EnvelopedCredential, proof: Proof): Promise<void> {
    await this.post("/v1alpha1/vc/revoke", { vc, proof });
  }

  // ---------- ID Service ----------

  /**
   * Generate an ID and its corresponding ResolverMetadata for a specified Issuer.
   * POST /v1alpha1/id/generate
   */
  async generateId(request: GenerateRequest): Promise<GenerateResponse> {
    return this.post<GenerateResponse>("/v1alpha1/id/generate", request);
  }

  /**
   * Resolve an ID to its corresponding ResolverMetadata.
   * POST /v1alpha1/id/resolve
   */
  async resolveId(id: string): Promise<ResolveResponse> {
    return this.post<ResolveResponse>("/v1alpha1/id/resolve", { id });
  }

  // ---------- Issuer Service ----------

  /**
   * Register an issuer.
   * POST /v1alpha1/issuer/register
   */
  async registerIssuer(
    issuer: Issuer,
    proof?: Proof,
  ): Promise<RegisterIssuerResponse> {
    return this.post<RegisterIssuerResponse>("/v1alpha1/issuer/register", {
      issuer,
      proof,
    });
  }

  /**
   * Get the well-known JWKS document for an issuer.
   * GET /v1alpha1/issuer/{commonName}/.well-known/jwks.json
   */
  async getIssuerWellKnown(
    commonName: string,
  ): Promise<GetIssuerWellKnownResponse> {
    return this.get<GetIssuerWellKnownResponse>(
      `/v1alpha1/issuer/${encodeURIComponent(commonName)}/.well-known/jwks.json`,
    );
  }

  // ---------- HTTP helpers ----------

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetch(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: this.headers,
    });
    return this.handleResponse<T>(res);
  }

  private async post<T = void>(path: string, body: unknown): Promise<T> {
    const res = await this.fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(body),
    });
    return this.handleResponse<T>(res);
  }

  private async handleResponse<T>(res: Response): Promise<T> {
    if (!res.ok) {
      let body: unknown;
      try {
        body = await res.json();
      } catch {
        body = await res.text();
      }
      throw new IdentityApiError(res.status, body);
    }
    const text = await res.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }
}
