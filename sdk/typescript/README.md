# @agntcy/identity-sdk

TypeScript SDK for the [AGNTCY Identity](https://github.com/agntcy/identity) service.

## Installation

```bash
npm install @agntcy/identity-sdk
```

## Usage

```typescript
import { IdentitySdk, CredentialEnvelopeType } from "@agntcy/identity-sdk";

const sdk = new IdentitySdk({
  baseUrl: "https://identity.example.com",
  headers: { Authorization: "Bearer <token>" }, // optional
});

// Get badge (well-known VCs) for an ID
const badge = await sdk.getBadge("did:example:123");

// Verify a credential
const result = await sdk.verifyBadge(badge);
console.log("Valid:", result.status);

// Publish a credential
await sdk.publish(
  { envelopeType: CredentialEnvelopeType.JOSE, value: "eyJ..." },
  { type: "jwt", proofPurpose: "assertionMethod", proofValue: "sig" },
);

// Search for credentials
const searchResult = await sdk.search({
  id: "did:example:123",
  schema: { type: "JsonSchema", id: "https://example.com/schema" },
  content: '{"name":"agent"}',
});

// Revoke a credential (irreversible)
await sdk.revoke(
  { envelopeType: CredentialEnvelopeType.JOSE, value: "eyJ..." },
  { type: "jwt", proofPurpose: "assertionMethod", proofValue: "sig" },
);

// ID Service - generate and resolve
const generated = await sdk.generateId({
  issuer: { commonName: "myissuer.com" },
});

const resolved = await sdk.resolveId("did:example:456");

// Issuer Service - register and get JWKS
await sdk.registerIssuer({ commonName: "myissuer.com" });
const jwks = await sdk.getIssuerWellKnown("myissuer.com");
```

## API

### `IdentitySdk(options)`

| Option | Type | Description |
|--------|------|-------------|
| `baseUrl` | `string` | Base URL of the Identity HTTP/JSON gateway |
| `fetch` | `typeof fetch` | Custom fetch implementation (optional) |
| `headers` | `Record<string, string>` | Extra headers for every request (optional) |

### VC Service Methods
- `getBadge(badgeId)` — Get the first well-known VC for an ID
- `getWellKnownVcs(badgeId)` — Get all well-known VCs for an ID
- `verifyBadge(badge)` — Verify a Verifiable Credential
- `publish(vc, proof?)` — Publish a Verifiable Credential
- `search(criteria)` — Search for VCs
- `revoke(vc, proof)` — Revoke a VC (irreversible)

### ID Service Methods
- `generateId(request)` — Generate an ID and ResolverMetadata
- `resolveId(id)` — Resolve an ID to ResolverMetadata

### Issuer Service Methods
- `registerIssuer(issuer, proof?)` — Register an issuer
- `getIssuerWellKnown(commonName)` — Get issuer's JWKS document

## License

Apache-2.0
