// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "github.com/agntcy/dir/api/core/v1"
	identityv1 "github.com/agntcy/dir/api/identity/v1"
	clientjws "github.com/agntcy/dir/client/utils/jws"
	agntcy "github.com/agntcy/identity/integrations/directory-verifier/protocol"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func compactBadge(t *testing.T, key ed25519.PrivateKey, value any) string {
	t.Helper()

	data, err := json.Marshal(value)
	require.NoError(t, err)
	sig, err := clientjws.Sign(key, data)
	require.NoError(t, err)

	parts := strings.Split(sig, ".")

	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(data) + "." + parts[2]
}

func TestVerifierWithIdentityNode(t *testing.T) {
	agentPub, agentKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicJWK, err := jwk.FromRaw(agentPub)
	require.NoError(t, err)
	agentJWK, err := json.Marshal(publicJWK)
	require.NoError(t, err)

	definition := map[string]any{"name": "security-agent", "version": "1", "annotations": map[string]any{"agntcy.dir/identity": "agntcy://Agent-One"}}
	data, err := structpb.NewStruct(definition)
	require.NoError(t, err)

	record := &corev1.Record{Data: data}
	claim := &identityv1.Claim{Role: identityv1.ClaimRole_CLAIM_ROLE_IDENTITY, Subject: "agntcy://Agent-One", RecordCid: record.GetCid(), SignedAt: time.Now().UTC().Format(time.RFC3339)}
	payload, err := claim.GetPayload()
	require.NoError(t, err)
	claim.Signature, err = clientjws.Sign(agentKey, payload)
	require.NoError(t, err)

	badgeExpiry := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	badgeSubject := map[string]any{"id": "Agent-One", "badge": definition}
	credential := map[string]any{"type": []string{"VerifiableCredential", "AgentBadge"}, "validUntil": badgeExpiry.Format(time.RFC3339), "credentialSubject": badgeSubject}

	var badge atomic.Value
	badge.Store(compactBadge(t, agentKey, credential))

	var identityAvailable atomic.Bool
	identityAvailable.Store(true)

	var badgeAccepted atomic.Bool
	badgeAccepted.Store(true)

	var identityKeysAvailable atomic.Bool
	identityKeysAvailable.Store(true)

	var keyCalls, badgeCalls atomic.Int32
	var assertionAuthorized atomic.Bool
	assertionAuthorized.Store(true)

	node := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-token" {
			t.Error("missing configured Node gateway token")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !identityAvailable.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)

			return
		}

		switch r.URL.Path {
		case "/v1alpha1/id/resolve":
			keyCalls.Add(1)
			methods := []map[string]any{}
			if identityKeysAvailable.Load() {
				methods = append(methods, map[string]any{"id": "Agent-One#key", "publicKeyJwk": json.RawMessage(agentJWK)})
			}

			assertions := []string{"#key"}
			if !assertionAuthorized.Load() {
				assertions = nil
			}
			writeJSON(w, map[string]any{"resolverMetadata": map[string]any{"id": "Agent-One", "verificationMethod": methods, "assertionMethod": assertions}})
		case "/v1alpha1/vc/Agent-One/.well-known/vcs.json":
			badgeCalls.Add(1)
			currentBadge, ok := badge.Load().(string)
			if !ok {
				t.Error("invalid badge fixture")

				return
			}

			writeJSON(w, wellKnownResponse{VCs: []credentialEnvelope{{EnvelopeType: "CREDENTIAL_ENVELOPE_TYPE_JOSE", Value: currentBadge}}})
		case "/v1alpha1/vc/verify":
			writeJSON(w, verifyResponse{Status: badgeAccepted.Load()})
		default:
			http.NotFound(w, r)
		}
	}))
	defer node.Close()

	resultKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	s := &server{identityURL: node.URL, verifierID: "agntcy-identity-verifier", privateKey: resultKey, client: node.Client(), token: "test-token", nodeToken: "node-token", ttl: 30 * time.Minute}

	verifier := httptest.NewTLSServer(s.handler())
	defer verifier.Close()

	r := &testClient{client: verifier.Client(), url: verifier.URL, key: &resultKey.PublicKey}
	result, err := r.verify(context.Background(), claim)
	require.NoError(t, err)
	require.True(t, result.Checks.Identity)
	require.True(t, result.Checks.Badge)
	require.Len(t, result.PublicKeys, 1)
	until, err := time.Parse(time.RFC3339, result.ExpiresAt)
	require.NoError(t, err)
	assert.True(t, until.Equal(badgeExpiry), "badge expiry must bound the signed observation")

	t.Run("control-only profile skips badge APIs", func(t *testing.T) {
		beforeKeys, beforeBadges := keyCalls.Load(), badgeCalls.Load()
		result, err := r.verifyProfile(context.Background(), claim, agntcy.KeyProfile)
		require.NoError(t, err)
		require.True(t, result.Checks.Identity)
		require.False(t, result.Checks.Badge)
		assert.Equal(t, beforeKeys+1, keyCalls.Load(), "one identity resolution per combined request")
		assert.Equal(t, beforeBadges, badgeCalls.Load(), "control-only must not fetch badges")
	})
	t.Run("published key without assertion authorization is rejected", func(t *testing.T) {
		assertionAuthorized.Store(false)
		defer assertionAuthorized.Store(true)
		_, err := r.verify(context.Background(), claim)
		require.Error(t, err)
	})
	t.Run("different record CID", func(t *testing.T) {
		other, ok := proto.Clone(claim).(*identityv1.Claim)
		require.True(t, ok)

		other.RecordCid = "other-cid"
		otherPayload, err := other.GetPayload()
		require.NoError(t, err)
		other.Signature, err = clientjws.Sign(agentKey, otherPayload)
		require.NoError(t, err)
		_, err = r.verify(context.Background(), other)
		require.Error(t, err)
	})
	t.Run("wrong badge subject", func(t *testing.T) {
		subject := badgeSubject
		subject["id"] = "Other"

		badge.Store(compactBadge(t, agentKey, credential))

		_, err := r.verify(context.Background(), claim)
		require.Error(t, err)

		subject["id"] = "Agent-One"

		badge.Store(compactBadge(t, agentKey, credential))
	})
	t.Run("different definition", func(t *testing.T) {
		definition["version"] = "2"

		badge.Store(compactBadge(t, agentKey, credential))

		_, err := r.verify(context.Background(), claim)
		require.Error(t, err)

		definition["version"] = "1"

		badge.Store(compactBadge(t, agentKey, credential))
	})
	t.Run("expired badge", func(t *testing.T) {
		credential["validUntil"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		badge.Store(compactBadge(t, agentKey, credential))

		_, err := r.verify(context.Background(), claim)
		require.Error(t, err)

		credential["validUntil"] = badgeExpiry.Format(time.RFC3339)
		badge.Store(compactBadge(t, agentKey, credential))
	})
	t.Run("node rejects badge", func(t *testing.T) {
		badgeAccepted.Store(false)

		_, err := r.verify(context.Background(), claim)
		require.Error(t, err)
		badgeAccepted.Store(true)
	})
	t.Run("withdrawn keys are authoritative rejection", func(t *testing.T) {
		identityKeysAvailable.Store(false)

		_, err := r.verify(context.Background(), claim)
		require.ErrorContains(t, err, "rejected")
		identityKeysAvailable.Store(true)
	})
	t.Run("temporary node failure", func(t *testing.T) {
		identityAvailable.Store(false)

		_, err := r.verify(context.Background(), claim)
		require.ErrorContains(t, err, "503")
		identityAvailable.Store(true)
	})
	t.Run("authentication required", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, verifier.URL+"/v1/verify", bytes.NewReader([]byte(`{}`)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := verifier.Client().Do(req)
		require.NoError(t, err)

		defer func() { assert.NoError(t, resp.Body.Close()) }()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestCanonicalPayloadIncludesRoleAndExpiry(t *testing.T) {
	claim := &identityv1.Claim{Role: identityv1.ClaimRole_CLAIM_ROLE_IDENTITY, RecordCid: "cid", Subject: "agntcy://Agent", SignedAt: time.Now().UTC().Format(time.RFC3339)}
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	claim.ExpiresAt = &until
	payload, err := claim.GetPayload()
	require.NoError(t, err)
	parsed, err := parseCanonicalPayload(payload, "signature")
	require.NoError(t, err)
	assert.Equal(t, claim.GetExpiresAt(), parsed.GetExpiresAt())
	assert.Equal(t, claim.GetRole(), parsed.GetRole())

	for _, invalid := range [][]byte{[]byte("cid|agntcy:Agent|timestamp"), append(payload, []byte(" {}")...), bytes.Replace(payload, []byte("CLAIM_ROLE_IDENTITY"), []byte("not-a-role"), 1)} {
		_, err := parseCanonicalPayload(invalid, "signature")
		require.Error(t, err)
	}
}

// testClient authenticates the real service response without depending on the
// Directory draft client. Live interoperability is tested from Directory.
type testClient struct {
	client *http.Client
	url    string
	key    *rsa.PublicKey
}

func (c *testClient) verify(ctx context.Context, claim *identityv1.Claim) (agntcy.VerificationResult, error) {
	return c.verifyProfile(ctx, claim, agntcy.Profile)
}

func (c *testClient) verifyProfile(ctx context.Context, claim *identityv1.Claim, profile string) (agntcy.VerificationResult, error) {
	var result agntcy.VerificationResult
	payload, err := claim.GetPayload()
	if err != nil {
		return result, err
	}
	input := agntcy.VerificationRequest{Profile: profile, Subject: claim.GetSubject(), Signature: claim.GetSignature(), Payload: base64.RawURLEncoding.EncodeToString(payload), Nonce: strings.Repeat("a", 64)}
	body, err := json.Marshal(input)
	if err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v1/verify", bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := c.client.Do(req)
	if err != nil {
		return result, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("verifier HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	var envelope agntcy.VerificationResponse
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return result, err
	}
	parts := strings.Split(envelope.ResultJWS, ".")
	if len(parts) != 3 {
		return result, fmt.Errorf("invalid result envelope")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return result, err
	}
	if err := clientjws.Verify(parts[0]+".."+parts[2], data, c.key); err != nil {
		return result, err
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	if result.RequestDigest != agntcy.DigestRequest(body) || result.Subject != claim.GetSubject() || result.RecordCID != claim.GetRecordCid() {
		return result, fmt.Errorf("result binding mismatch")
	}
	if !result.Verified {
		return result, fmt.Errorf("verifier rejected: %s", result.Error)
	}
	return result, nil
}

func TestNonceFormat(t *testing.T) {
	assert.True(t, validNonce(strings.Repeat("a", 64)))
	assert.False(t, validNonce(strings.Repeat("a", 63)))
	assert.False(t, validNonce(strings.Repeat("z", 64)))
}
