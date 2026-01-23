// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	identitycache "github.com/agntcy/identity/internal/pkg/cache"
	"github.com/agntcy/identity/internal/pkg/httputil"
	"github.com/agntcy/identity/internal/pkg/log"
	"github.com/coocood/freecache"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	freecache_store "github.com/eko/gocache/store/freecache/v4"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type Claims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	SubJWK  string `json:"sub_jwk"` // used for self-issued tokens
}

type ProviderName int

const (
	UnknownProviderName ProviderName = iota
	OktaProviderName
	DuoProviderName
	OryProviderName
	IdpProviderName
	PingProviderName
	SelfProviderName
)

type ParsedJWT struct {
	Claims           *Claims
	Provider         ProviderName
	CommonName       string
	providerMetadata *providerMetadata
	jwt              *string
}

type providerMetadata struct {
	Issuer   string `json:"issuer"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
}

const (
	defaultCacheSize       = 10 * 1024 * 1024 // 10MB
	defaultCacheExpiration = 24               // 24 hours
	defaultAcceptableSkew  = 5 * time.Second  // 5 seconds
)

type CachedJwks struct {
	Jwks string
}

// The Parser defines different methods for the PARSER standard
type Parser interface {
	// VerifyJwt verifies the provided JWT signature.
	// If the JWT is not self-issued (provider = SelfProviderName) it will validate
	// the token using the public key located in the claims (sub_jwk).
	// Else, it will attempt to retrieve the JWKS from the issuer's metadata.
	VerifyJwt(ctx context.Context, jwt *ParsedJWT) error

	// Get the parsed JWT including the issuer, the subject claims
	// the common name and the provider metadata
	ParseJwt(ctx context.Context, jwtString *string) (*ParsedJWT, error)
}

// The parser struct implements the Parser interface
type parser struct {
	jwksCache *cache.Cache[[]byte]
}

// NewParser creates a new instance of the Parser
func NewParser() Parser {
	jwksCache := cache.New[[]byte](
		freecache_store.NewFreecache(
			freecache.NewCache(defaultCacheSize),
			store.WithExpiration(defaultCacheExpiration*time.Second),
		))

	return &parser{
		jwksCache,
	}
}

func (p *parser) VerifyJwt(ctx context.Context, parsedJwt *ParsedJWT) error {
	if parsedJwt == nil {
		return errors.New("the jwt provided is nil or was parsed incorrectly")
	}

	var err error

	var jwks jwk.Set

	if parsedJwt.Provider != SelfProviderName {
		// Get the JWKS from the issuer
		jwks, err = p.getJwks(ctx, parsedJwt.providerMetadata)
		if err != nil {
			return fmt.Errorf("failed to get JWKS from issuer: %w", err)
		}
	} else {
		log.Debug("Using issuer's self generated JWKS")

		key, err := jwk.ParseKey([]byte(parsedJwt.Claims.SubJWK))
		if err != nil {
			return fmt.Errorf("failed to parse JWKS: %w", err)
		}

		jwks = jwk.NewSet()
		_ = jwks.AddKey(key)
	}

	// Verify with full key set
	log.Debug("Attempting verification with full key set")

	_, err = jws.Verify(
		[]byte(*parsedJwt.jwt),
		jws.WithKeySet(jwks, jws.WithInferAlgorithmFromKey(true)), // Some issuer like Entra don't include the alg in the jwk.
	)
	if err != nil {
		log.Debug("Verification with key set FAILED:", err)
		return err
	}

	return nil
}

func (p *parser) ParseJwt(
	ctx context.Context,
	jwtString *string,
) (*ParsedJWT, error) {
	if jwtString == nil || *jwtString == "" {
		return nil, errors.New("JWT string is empty")
	}

	claims, err := p.GetClaims(ctx, jwtString)
	if err != nil {
		return nil, err
	}

	log.Debug("Validating JWT for issuer:", claims.Issuer, " and subject:", claims.Subject)

	var providerName ProviderName

	var commonName string

	var providerMD *providerMetadata

	selfIssued, err := p.isSelfIssuedToken(claims)
	if err != nil {
		return nil, err
	}

	if selfIssued {
		log.Debug("The JWT is self-issued")

		providerName = SelfProviderName

		// Remove the self-issued scheme from the issuer to get the common name
		commonName, _ = strings.CutPrefix(claims.Issuer, SelfIssuedIssScheme+":")
	} else {
		providerMD, err = getProviderMetadata(ctx, claims.Issuer)
		if err != nil {
			return nil, err
		}

		providerName, err = p.detectProviderName(ctx, providerMD)
		if err != nil {
			return nil, err
		}

		// Use full issuer URL as common name when available in metadata
		// (this handles Entra and other v2.0 endpoints correctly)
		if providerMD.Issuer != "" {
			commonName = providerMD.Issuer
		} else {
			commonName = httputil.Hostname(claims.Issuer)
		}
	}

	return &ParsedJWT{
		Claims:           claims,
		Provider:         providerName,
		CommonName:       commonName,
		providerMetadata: providerMD,
		jwt:              jwtString,
	}, nil
}

func (p *parser) GetClaims(
	ctx context.Context,
	jwtString *string,
) (*Claims, error) {
	jwtToken, err := jwt.Parse(
		[]byte(*jwtString),
		jwt.WithVerify(false),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(defaultAcceptableSkew),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	issuer, ok := jwtToken.Issuer()
	if !ok {
		return nil, errors.New("failed to decode JWT: missing 'iss' claim")
	}

	var subOk bool

	var cidError, clientIDError error

	var sub, cid, clientID string

	// Get the subject from 'sub', 'cid' or 'client_id' claim
	sub, subOk = jwtToken.Subject()
	cidError = jwtToken.Get("cid", &cid)
	clientIDError = jwtToken.Get("client_id", &clientID)

	if !subOk && cidError != nil && clientIDError != nil {
		return nil, errors.New("failed to decode JWT: missing 'sub', 'cid' or 'client_id' claim")
	}

	subject := sub
	if subject == "" {
		if cidError == nil && cid != "" {
			subject = cid
		} else if clientIDError == nil && clientID != "" {
			subject = clientID
		}
	}

	var subJWK map[string]any

	var jsonSubJWK []byte

	err = jwtToken.Get(SelfIssuedTokenSubJwkClaimName, &subJWK)
	if err == nil {
		jsonSubJWK, err = json.Marshal(subJWK)
		if err != nil {
			return nil, fmt.Errorf("failed to decode JWT: invalid 'sub_jwk' claim: %w", err)
		}
	}

	return &Claims{
		Issuer:  issuer,
		Subject: subject,
		SubJWK:  string(jsonSubJWK),
	}, nil
}

func (p *parser) isSelfIssuedToken(claims *Claims) (bool, error) {
	u, err := url.Parse(claims.Issuer)
	if err != nil {
		return false, err
	}

	return strings.EqualFold(u.Scheme, SelfIssuedIssScheme), nil
}

func (p *parser) getJwks(ctx context.Context, provider *providerMetadata) (jwk.Set, error) {
	cachedEntry, found := identitycache.GetFromCache[CachedJwks](ctx, p.jwksCache, provider.Issuer)
	if found {
		return p.parseJwks(&cachedEntry.Jwks)
	}

	var jwksString string

	err := httputil.GetWithRawBody(ctx, provider.JWKSURL, nil, &jwksString)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS from issuer: %w", err)
	}

	jwks, err := p.parseJwks(&jwksString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	err = identitycache.AddToCache(ctx, p.jwksCache, provider.Issuer, &CachedJwks{Jwks: jwksString})
	if err != nil {
		log.Warn(err)
	}

	return jwks, nil
}

func (p *parser) parseJwks(jwksString *string) (jwk.Set, error) {
	if jwksString == nil || *jwksString == "" {
		return nil, errors.New("JWKS string is empty")
	}

	jwks, err := jwk.Parse([]byte(*jwksString))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return jwks, nil
}
