// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	identitycache "github.com/agntcy/identity/internal/pkg/cache"
	"github.com/agntcy/identity/internal/pkg/errutil"
	"github.com/agntcy/identity/internal/pkg/httputil"
	"github.com/agntcy/identity/pkg/log"
	freecache "github.com/coocood/freecache"
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

const defaultCacheSize = 10 * 1024 * 1024     // 10MB
const defaultCacheExpiration = 24             // 24 hours
const defaultAcceptableSkew = 5 * time.Second // 5 seconds

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
		return errutil.Err(
			nil,
			"the jwt provided is nil or was parsed incorrectly",
		)
	}

	var err error
	var jwks jwk.Set

	if parsedJwt.Provider != SelfProviderName {
		// Get the JWKS from the issuer
		jwks, err = p.getJwks(ctx, parsedJwt.providerMetadata)
		if err != nil {
			return errutil.Err(err, "failed to get JWKS from issuer")
		}
	} else {
		log.Debug("Using issuer's self generated JWKS")

		key, err := jwk.ParseKey([]byte(parsedJwt.Claims.SubJWK))
		if err != nil {
			return errutil.Err(err, "failed to parse JWKS")
		}

		jwks = jwk.NewSet()
		_ = jwks.AddKey(key)
	}

	// Verify the JWT signature
	_, err = jws.Verify([]byte(*parsedJwt.jwt), jws.WithKeySet(jwks))
	if err != nil {
		return err
	}

	return nil
}

func (p *parser) ParseJwt(
	ctx context.Context,
	jwtString *string,
) (*ParsedJWT, error) {
	if jwtString == nil || *jwtString == "" {
		return nil, errutil.Err(nil, "JWT string is empty")
	}

	claims, err := p.GetClaims(ctx, jwtString)
	if err != nil {
		return nil, err
	}

	log.Debug("Validating JWT for issuer:", claims.Issuer, " and subject:", claims.Subject)

	var providerName ProviderName
	var commonName string
	var someProviderMetadata *providerMetadata

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
		var pMetadata *providerMetadata
		var err error

		// Attempt to get the provider metadata from the OIDC well-known URL
		pMetadata, err = p.getProviderMetadata(ctx, claims.Issuer, p.getOidcWellKnownURL(claims.Issuer))
		if err != nil {
			// If OIDC well-known URL fails, try OAuth well-known URL
			pMetadata, err = p.getProviderMetadata(ctx, claims.Issuer, p.getOauthWellKnownURL(claims.Issuer))
			if err != nil {
				return nil, err
			}
		}

		someProviderMetadata = pMetadata

		providerName, err = p.detectProviderName(ctx, someProviderMetadata)
		if err != nil {
			return nil, err
		}

		commonName = httputil.Hostname(claims.Issuer)
	}

	return &ParsedJWT{
		Claims:           claims,
		Provider:         providerName,
		CommonName:       commonName,
		providerMetadata: someProviderMetadata,
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
		return nil, errutil.Err(err, "failed to parse JWT")
	}

	issuer, ok := jwtToken.Issuer()
	if !ok {
		return nil, errutil.Err(nil, "failed to decode JWT: missing 'iss' claim")
	}

	subject, ok := jwtToken.Subject()
	if !ok {
		return nil, errutil.Err(nil, "failed to decode JWT: missing 'sub' claim")
	}

	var subJWK map[string]any
	var jsonSubJWK []byte

	err = jwtToken.Get(SelfIssuedTokenSubJwkClaimName, &subJWK)
	if err == nil {
		jsonSubJWK, err = json.Marshal(subJWK)
		if err != nil {
			return nil, errutil.Err(err, "failed to decode JWT: invalid 'sub_jwk' claim")
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

func (p *parser) getOidcWellKnownURL(issuer string) string {
	return issuer + "/.well-known/openid-configuration"
}

func (p *parser) getOauthWellKnownURL(issuer string) string {
	// Get host and path from the issuer URL
	u, err := url.Parse(issuer)
	if err != nil {
		log.Error("Failed to parse issuer URL:", err)
		return ""
	}

	// Construct the well-known URL for OAuth
	return u.Scheme + "://" + u.Host + "/.well-known/oauth-authorization-server/" + u.Path
}

func (p *parser) getProviderMetadata(
	ctx context.Context,
	issuer string,
	wellKnownURL string,
) (*providerMetadata, error) {
	log.Debug("Getting metadata from issuer:", issuer, " with URL:", wellKnownURL)

	var metadata providerMetadata

	err := httputil.GetJSON(ctx, wellKnownURL, &metadata)
	if err != nil {
		return nil, errutil.Err(err, "failed to get metadata from issuer")
	}

	log.Debug("Got metadata from issuer:", metadata)

	return &metadata, nil
}

func (p *parser) getJwks(ctx context.Context, provider *providerMetadata) (jwk.Set, error) {
	cachedEntry, found := identitycache.GetFromCache[CachedJwks](ctx, p.jwksCache, provider.Issuer)
	if found {
		return p.parseJwks(&cachedEntry.Jwks)
	}

	var jwksString string

	err := httputil.GetWithRawBody(ctx, provider.JWKSURL, nil, &jwksString)
	if err != nil {
		return nil, errutil.Err(err, "failed to get JWKS from issuer")
	}

	jwks, err := p.parseJwks(&jwksString)
	if err != nil {
		return nil, errutil.Err(err, "failed to parse JWKS")
	}

	err = identitycache.AddToCache(ctx, p.jwksCache, provider.Issuer, &CachedJwks{Jwks: jwksString})
	if err != nil {
		log.Warn(err)
	}

	return jwks, nil
}

func (p *parser) parseJwks(jwksString *string) (jwk.Set, error) {
	if jwksString == nil || *jwksString == "" {
		return nil, errutil.Err(nil, "JWKS string is empty")
	}

	jwks, err := jwk.Parse([]byte(*jwksString))
	if err != nil {
		return nil, errutil.Err(err, "failed to parse JWKS")
	}

	return jwks, nil
}
