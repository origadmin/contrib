/* * Copyright (c) 2024 OrigAdmin. All rights reserved. */

// Package jwt provides a JWT-based implementation of the security interfaces.
package jwt

import (
	"context"
	"errors"
	"time"

	"github.com/dchest/uniuri"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	authnFactory "github.com/origadmin/contrib/security/authn"
	securitycache "github.com/origadmin/contrib/security/authn/cache"
	securityCredential "github.com/origadmin/contrib/security/credential"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

const (
	defaultIssuer          = "origadmin"
	defaultAccessTokenTTL  = 2 * time.Hour
	defaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// Authenticator implements the security interfaces for JWT.
type Authenticator struct {
	keyFunc              jwtv5.Keyfunc
	signingMethod        jwtv5.SigningMethod
	issuer               string
	audience             []string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	cache                securitycache.Cache
	generateID           func() string
	clock                func() time.Time
	skipAudienceCheck    bool
}

// NewProvider creates a new JWT Provider from the given configuration and options.
func NewProvider(cfg *authnv1.Authenticator, opts ...options.Option) (authnFactory.Provider, error) {
	jwtCfg := cfg.GetJwt()
	if jwtCfg == nil {
		return nil, securityv1.ErrorCredentialsInvalid("JWT configuration is missing")
	}
	o := FromOptions(opts...)
	if err := o.Apply(jwtCfg); err != nil {
		return nil, err
	}

	clock := o.clock
	if clock == nil {
		clock = time.Now
	}
	generateID := o.generateID
	if generateID == nil {
		generateID = uniuri.New
	}

	auth := &Authenticator{
		keyFunc:              o.keyFunc,
		signingMethod:        o.signingMethod,
		issuer:               o.issuer,
		audience:             o.audience,
		accessTokenLifetime:  o.accessTokenLifetime,
		refreshTokenLifetime: o.refreshTokenLifetime,
		cache:                o.cache,
		generateID:           generateID,
		clock:                clock,
		skipAudienceCheck:    len(o.audience) == 0,
	}

	return newProvider(auth, cfg), nil
}

// Authenticate validates the provided credential and returns a Principal if successful.
func (a *Authenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	if !a.Supports(cred) {
		return nil, securityv1.ErrorCredentialsInvalid("unsupported credential type: %s", cred.Type())
	}

	var bc securityv1.BearerCredential
	if err := cred.ParsedPayload(&bc); err != nil {
		return nil, securityv1.ErrorBearerTokenInvalid("failed to parse bearer credential: %v", err)
	}
	tokenStr := bc.GetToken()
	if tokenStr == "" {
		return nil, securityv1.ErrorTokenMissing("token is empty")
	}

	claims, err := a.parseAndValidateToken(tokenStr, false) // Full validation for authentication
	if err != nil {
		return nil, err
	}

	if a.cache != nil {
		if claims.ID == "" {
			return nil, securityv1.ErrorClaimsInvalid("missing 'jti' claim for revocation check")
		}
		isRevoked, err := a.isTokenRevoked(ctx, claims.ID)
		if err != nil {
			log.Warnf("Failed to check token revocation status: %v", err)
			return nil, securityv1.ErrorTokenInvalid("token revocation check failed: %v", err)
		}
		if isRevoked {
			return nil, securityv1.ErrorTokenExpired("token has been revoked")
		}
	}

	if claims.Subject == "" {
		return nil, securityv1.ErrorClaimsInvalid("missing or invalid 'sub' claim")
	}

	p := securityPrincipal.New(
		claims.Subject,
		claims.Roles,
		claims.Permissions,
		claims.Scopes,
		claims,
	)

	return p, nil
}

// Supports returns true if this authenticator can handle the given credential.
func (a *Authenticator) Supports(cred security.Credential) bool {
	return cred.Type() == "jwt"
}

// CreateCredential issues a new credential for the given principal.
func (a *Authenticator) CreateCredential(ctx context.Context, p security.Principal) (security.CredentialResponse, error) {
	now := a.clock()
	accessTokenID := a.generateID()

	accessClaims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    a.issuer,
			Subject:   p.GetID(),
			Audience:  a.audience,
			ExpiresAt: jwtv5.NewNumericDate(now.Add(a.accessTokenLifetime)),
			NotBefore: jwtv5.NewNumericDate(now),
			IssuedAt:  jwtv5.NewNumericDate(now),
			ID:        accessTokenID,
		},
		Roles:       p.GetRoles(),
		Permissions: p.GetPermissions(),
		Scopes:      p.GetScopes(),
	}
	accessToken, err := a.signToken(accessClaims)
	if err != nil {
		return nil, err
	}

	refreshClaims := &jwtv5.RegisteredClaims{
		Issuer:    a.issuer,
		Subject:   p.GetID(),
		Audience:  a.audience,
		ExpiresAt: jwtv5.NewNumericDate(now.Add(a.refreshTokenLifetime)),
		NotBefore: jwtv5.NewNumericDate(now),
		IssuedAt:  jwtv5.NewNumericDate(now),
		ID:        a.generateID(),
	}
	refreshToken, err := a.signToken(refreshClaims)
	if err != nil {
		return nil, err
	}

	tokenCred := &securityv1.TokenCredential{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(a.accessTokenLifetime.Seconds()),
		TokenType:    "Bearer",
	}

	payload := &securityv1.Payload{
		Token: tokenCred,
	}

	return securityCredential.NewCredentialResponse("jwt", payload, make(map[string][]string)), nil
}

// Revoke invalidates the given credential.
func (a *Authenticator) Revoke(ctx context.Context, cred security.Credential) error {
	if a.cache == nil {
		return securityv1.ErrorSigningMethodUnsupported("cache is not configured for token revocation")
	}

	if !a.Supports(cred) {
		return securityv1.ErrorCredentialsInvalid("unsupported credential type for revocation: %s", cred.Type())
	}

	var bc securityv1.BearerCredential
	if err := cred.ParsedPayload(&bc); err != nil {
		return securityv1.ErrorBearerTokenInvalid("failed to parse bearer credential for revocation: %v", err)
	}
	tokenStr := bc.GetToken()
	if tokenStr == "" {
		return securityv1.ErrorTokenMissing("token is empty for revocation")
	}

	// For revocation, we only need the claims, and we can ignore if the token is already expired.
	claims, err := a.parseAndValidateToken(tokenStr, true) // `true` to skip expiration check
	if err != nil {
		// Any error other than expiration is still a problem (e.g., bad signature).
		return err
	}

	if claims.ID == "" {
		return securityv1.ErrorClaimsInvalid("missing 'jti' claim for revocation")
	}

	// We still need the expiration time to set a TTL on the revocation entry in the cache.
	if claims.ExpiresAt == nil {
		return securityv1.ErrorClaimsInvalid("missing or invalid 'exp' claim for revocation")
	}

	remainingTTL := time.Until(claims.ExpiresAt.Time)
	if remainingTTL <= 0 {
		return nil // Already expired, no need to add to cache.
	}

	if err := a.cache.Store(ctx, revocationKey(claims.ID), remainingTTL); err != nil {
		return securityv1.ErrorTokenInvalid("failed to revoke token in cache: %v", err)
	}
	return nil
}

// isTokenRevoked checks if a token has been revoked.
func (a *Authenticator) isTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	return a.cache.Exist(ctx, revocationKey(tokenID))
}

// parseAndValidateToken parses a JWT string and validates its claims.
// If skipExpCheck is true, it will not return an error for expired tokens.
func (a *Authenticator) parseAndValidateToken(tokenStr string, skipExpCheck bool) (*Claims, error) {
	claims := &Claims{}
	parserOpts := []jwtv5.ParserOption{
		jwtv5.WithIssuer(a.issuer),
		jwtv5.WithTimeFunc(a.clock),
	}
	if !a.skipAudienceCheck {
		parserOpts = append(parserOpts, jwtv5.WithAudience(a.audience...))
	}

	parsedToken, err := jwtv5.ParseWithClaims(tokenStr, claims, a.keyFunc, parserOpts...)
	if err != nil {
		// If we are skipping the expiration check and the only error is expiration, return the claims.
		if skipExpCheck && errors.Is(err, jwtv5.ErrTokenExpired) {
			// The token is expired, but the caller wants to proceed, so we return the parsed claims.
			// The claims are still populated even when this error occurs.
			return claims, nil
		}
		return nil, mapJWTError(err)
	}

	if !parsedToken.Valid {
		return nil, securityv1.ErrorTokenInvalid("token is invalid")
	}

	return claims, nil
}

// signToken creates and signs a JWT string for the given claims.
func (a *Authenticator) signToken(claims jwtv5.Claims) (string, error) {
	token := jwtv5.NewWithClaims(a.signingMethod, claims)
	key, err := a.keyFunc(token)
	if err != nil {
		return "", securityv1.ErrorTokenSignFailed("failed to get signing key: %v", err)
	}
	return token.SignedString(key)
}

// revocationKey creates a standard key for storing revocation status in the cache.
func revocationKey(tokenID string) string {
	return "jwt:revoked:" + tokenID
}

// mapJWTError maps errors from the jwt-go library to our internal error types.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwtv5.ErrTokenMalformed):
		return securityv1.ErrorTokenInvalid("token is malformed: %v", err)
	case errors.Is(err, jwtv5.ErrTokenSignatureInvalid):
		return securityv1.ErrorTokenInvalid("token signature is invalid: %v", err)
	case errors.Is(err, jwtv5.ErrTokenExpired):
		return securityv1.ErrorTokenExpired("token has expired: %v", err)
	case errors.Is(err, jwtv5.ErrTokenNotValidYet):
		return securityv1.ErrorTokenInvalid("token not valid yet: %v", err)
	case errors.Is(err, jwtv5.ErrTokenInvalidIssuer):
		return securityv1.ErrorClaimsInvalid("invalid issuer: %v", err)
	case errors.Is(err, jwtv5.ErrTokenInvalidAudience):
		return securityv1.ErrorClaimsInvalid("invalid audience: %v", err)
	default:
		return securityv1.ErrorTokenInvalid("unexpected token error: %v", err)
	}
}

// Interface compliance checks.
var (
	_ authnFactory.Authenticator = (*Authenticator)(nil)
	_ securityCredential.Creator = (*Authenticator)(nil)
	_ securityCredential.Revoker = (*Authenticator)(nil)
	_ security.Claims            = (*Claims)(nil)
)
