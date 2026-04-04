import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  IdentitySdk,
  IdentityApiError,
  CredentialEnvelopeType,
  type EnvelopedCredential,
  type Proof,
} from "../index.js";

function mockFetch(status: number, body: unknown): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(body)),
    json: () => Promise.resolve(body),
  } as Response);
}

describe("IdentitySdk", () => {
  const BASE = "https://identity.example.com";
  let fetchMock: ReturnType<typeof vi.fn>;
  let sdk: IdentitySdk;

  beforeEach(() => {
    fetchMock = mockFetch(200, {}) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });
  });

  // --- getBadge ---
  it("getBadge calls correct URL and returns first VC", async () => {
    const vc: EnvelopedCredential = { envelopeType: CredentialEnvelopeType.JOSE, value: "jwt..." };
    fetchMock = mockFetch(200, { vcs: [vc] }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    const result = await sdk.getBadge("did:example:123");
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][0]).toBe(
      `${BASE}/v1alpha1/vc/did%3Aexample%3A123/.well-known/vcs.json`,
    );
    expect(result.value).toBe("jwt...");
  });

  it("getBadge throws when no VCs returned", async () => {
    fetchMock = mockFetch(200, { vcs: [] }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });
    await expect(sdk.getBadge("none")).rejects.toThrow("No badge found");
  });

  // --- verifyBadge ---
  it("verifyBadge POSTs to /verify", async () => {
    const badge: EnvelopedCredential = { envelopeType: CredentialEnvelopeType.JOSE, value: "x" };
    fetchMock = mockFetch(200, { status: true }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    const result = await sdk.verifyBadge(badge);
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/v1alpha1/vc/verify`);
    expect(fetchMock.mock.calls[0][1].method).toBe("POST");
    expect(result.status).toBe(true);
  });

  // --- publish ---
  it("publish POSTs vc and optional proof", async () => {
    const vc: EnvelopedCredential = { envelopeType: CredentialEnvelopeType.EMBEDDED_PROOF, value: "v" };
    const proof: Proof = { type: "jwt", proofValue: "sig" };
    fetchMock = mockFetch(200, {}) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    await sdk.publish(vc, proof);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.vc).toEqual(vc);
    expect(body.proof).toEqual(proof);
  });

  // --- search ---
  it("search POSTs criteria", async () => {
    fetchMock = mockFetch(200, { vcs: [] }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    const result = await sdk.search({
      id: "did:example:1",
      schema: { type: "JsonSchema", id: "s" },
      content: "{}",
    });
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/v1alpha1/vc/search`);
    expect(result.vcs).toEqual([]);
  });

  // --- revoke ---
  it("revoke POSTs vc and proof", async () => {
    const vc: EnvelopedCredential = { value: "v" };
    const proof: Proof = { proofValue: "sig" };
    fetchMock = mockFetch(200, {}) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    await sdk.revoke(vc, proof);
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/v1alpha1/vc/revoke`);
  });

  // --- generateId ---
  it("generateId POSTs issuer", async () => {
    fetchMock = mockFetch(200, { resolverMetadata: { id: "did:new" } }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    const res = await sdk.generateId({ issuer: { commonName: "test.com" } });
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/v1alpha1/id/generate`);
    expect(res.resolverMetadata.id).toBe("did:new");
  });

  // --- resolveId ---
  it("resolveId POSTs id", async () => {
    fetchMock = mockFetch(200, { resolverMetadata: { id: "did:x" } }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    const res = await sdk.resolveId("did:x");
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/v1alpha1/id/resolve`);
  });

  // --- registerIssuer ---
  it("registerIssuer POSTs issuer", async () => {
    fetchMock = mockFetch(200, {}) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    await sdk.registerIssuer({ commonName: "issuer.com" });
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/v1alpha1/issuer/register`);
  });

  // --- getIssuerWellKnown ---
  it("getIssuerWellKnown GETs correct URL", async () => {
    fetchMock = mockFetch(200, { jwks: { keys: [] } }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    const res = await sdk.getIssuerWellKnown("issuer.com");
    expect(fetchMock.mock.calls[0][0]).toBe(
      `${BASE}/v1alpha1/issuer/issuer.com/.well-known/jwks.json`,
    );
    expect(res.jwks.keys).toEqual([]);
  });

  // --- error handling ---
  it("throws IdentityApiError on non-OK response", async () => {
    fetchMock = mockFetch(404, { error: "not found" }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({ baseUrl: BASE, fetch: fetchMock });

    await expect(sdk.getBadge("missing")).rejects.toThrow(IdentityApiError);
    try {
      await sdk.getBadge("missing");
    } catch (e) {
      expect((e as IdentityApiError).statusCode).toBe(404);
    }
  });

  // --- custom headers ---
  it("sends custom headers", async () => {
    fetchMock = mockFetch(200, { vcs: [{ value: "x" }] }) as ReturnType<typeof vi.fn>;
    sdk = new IdentitySdk({
      baseUrl: BASE,
      fetch: fetchMock,
      headers: { Authorization: "Bearer token" },
    });

    await sdk.getBadge("id");
    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer token");
    expect(headers["Content-Type"]).toBe("application/json");
  });
});
