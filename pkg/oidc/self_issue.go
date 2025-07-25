// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/agntcy/identity/pkg/joseutil"
	"github.com/agntcy/identity/pkg/jwk"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	SelfIssuedTokenSubJwkClaimName string = "sub_jwk"
	SelfIssuedIssScheme            string = "agntcy"
)

func SelfIssueJWT(issuer, sub string, key *jwk.Jwk) (string, error) {
	tok, _ := jwt.NewBuilder().
		Issuer(fmt.Sprintf("%s:%s", SelfIssuedIssScheme, issuer)).
		Subject(sub).
		Audience([]string{sub}).
		Expiration(time.Now().Add(1*time.Hour)).
		IssuedAt(time.Now()).
		JwtID(uuid.NewString()).
		Claim(SelfIssuedTokenSubJwkClaimName, key.PublicKey()).
		Build()

	buf, err := json.Marshal(tok)
	if err != nil {
		return "", fmt.Errorf("failed to serialize token: %w", err)
	}

	token, err := joseutil.Sign(key, buf)
	if err != nil {
		return "", err
	}

	return string(token), nil
}
