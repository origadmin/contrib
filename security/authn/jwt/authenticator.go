/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package jwt provides a JWT-based implementation of the security interfaces.
package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dchest/uniuri"
	jwtv5 "github.com/golang-jwt/jwt/v5"

	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	securityCredential "github.com/origadmin/contrib/security/credential"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/log"
)

func init() {
	authn.Register(authn.JWT, authn.FactoryFunc(NewAuthenticator))
}

// Authenticator implements the security interfaces for JWT.
type Authenticator struct {
	*Options
	skipAudienceCheck bool // Derived internal state, not a direct Option
	log               *log.Helper
}

// NewOptions creates a new Options object from the given configuration and functional options.
func NewOptions(cfg *authnv1.Authenticator, opts ...Option) (*Options, error) {
	return newWithOptions(cfg, opts...)
}

// New creates a new Authenticator instance from a pre-built Options object and a logger.
func New(opts *Options, logger log.Logger) (*Authenticator, error) {
	helper := log.NewHelper(log.With(logger, "module", "security.authn.jwt"))

	auth := &Authenticator{
		Options:           opts,
		skipAudienceCheck: len(opts.audience) == 0,
		log:               helper,
	}

	auth.log.Debugf("JWT Authenticator initialized with issuer: %s", auth.issuer)

	return auth, nil
}

// NewAuthenticator creates a new JWT Provider from the given configuration and options.
func NewAuthenticator(cfg *authnv1.Authenticator, opts ...Option) (authn.Authenticator, error) {
	finalOpts, err := newWithOptions(cfg, opts...)
	if err != nil {
		return nil, err
	}

	return New(finalOpts, finalOpts.Logger)
}

// Authenticate validates the provided credential and returns a Principal if successful.
func (a *Authenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	if !a.Supports(cred) {
		return nil, securityv1.ErrorCredentialsInvalid("unsupported credential type: %s", cred.Type())
	}

	var bc securityv1.BearerCredential
	if err := cred.ParsedPayload(&bc); err != nil {
		a.log.WithContext(ctx).Warnf("Failed to parse bearer credential payload: %v", err)
		return nil, securityv1.ErrorBearerTokenInvalid("failed to parse bearer credential: %v", err)
	}
	tokenStr := bc.GetToken()
	if tokenStr == "" {
		return nil, securityv1.ErrorTokenMissing("token is empty")
	}

	claims, err := a.parseAndValidateToken(ctx, tokenStr, false)
	if err != nil {
		// The parse function already logs the specific error, no need for duplicate logging.
		return nil, err
	}

	if a.cache != nil {
		if claims.ID == "" {
			a.log.WithContext(ctx).Warn("Missing 'jti' claim for revocation check")
			return nil, securityv1.ErrorClaimsInvalid("missing 'jti' claim for revocation check")
		}
		isRevoked, err := a.isTokenRevoked(ctx, claims.ID)
		if err != nil {
			a.log.WithContext(ctx).Errorf("Failed to check token revocation status for ID %s: %v", claims.ID, err)
			return nil, securityv1.ErrorTokenInvalid("token revocation check failed: %v", err)
		}
		if isRevoked {
			a.log.WithContext(ctx).Warnf("Token with ID %s has been revoked", claims.ID)
			return nil, securityv1.ErrorTokenExpired("token has been revoked")
		}
	}

	if claims.Subject == "" {
		a.log.WithContext(ctx).Warn("Missing or invalid 'sub' claim in token")
		return nil, securityv1.ErrorClaimsInvalid("missing or invalid 'sub' claim")
	}

	p := securityPrincipal.New(
		claims.Subject,
		securityPrincipal.WithDomain(a.issuer),
		securityPrincipal.WithRoles(claims.Roles),
		securityPrincipal.WithPermissions(claims.Permissions),
		securityPrincipal.WithScopes(claims.Scopes),
		securityPrincipal.WithClaims(claims),
	)
	return p, nil
}

// Supports returns true if this authenticator can handle the given credential.
func (a *Authenticator) Supports(cred security.Credential) bool {
	return cred.Type() == authn.JWT
}

// CreateCredential issues a new credential for the given principal.
func (a *Authenticator) CreateCredential(ctx context.Context, p security.Principal) (security.CredentialResponse, error) {
	a.log.WithContext(ctx).Debugf("Creating credential for principal ID: %s", p.GetID())
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
	accessToken, err := a.signToken(ctx, accessClaims)
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
	refreshToken, err := a.signToken(ctx, refreshClaims)
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

	return securityCredential.NewCredentialResponse(authn.JWT, payload, make(map[string][]string)), nil
}

// RefreshCredential issues a new credential based on a valid refresh token.
func (a *Authenticator) RefreshCredential(ctx context.Context, refreshToken string) (security.CredentialResponse, error) {
	// 1. Parse and validate the refresh token.
	claims, err := a.parseAndValidateToken(ctx, refreshToken, false)
	if err != nil {
		return nil, err
	}

	// 2. Check if the refresh token has been revoked.
	if a.cache != nil {
		if claims.ID == "" {
			return nil, securityv1.ErrorClaimsInvalid("missing 'jti' claim in refresh token")
		}
		isRevoked, err := a.isTokenRevoked(ctx, claims.ID)
		if err != nil {
			return nil, securityv1.ErrorTokenInvalid("refresh token revocation check failed: %v", err)
		}
		if isRevoked {
			return nil, securityv1.ErrorTokenExpired("refresh token has been revoked")
		}
	}

	// 3. Ensure the subject exists.
	if claims.Subject == "" {
		return nil, securityv1.ErrorClaimsInvalid("missing 'sub' claim in refresh token")
	}

	// 4. Create a Principal from the refresh token claims.
	// Note: We trust the claims in the valid refresh token.
	p := securityPrincipal.New(
		claims.Subject,
		securityPrincipal.WithDomain(a.issuer),
		securityPrincipal.WithRoles(claims.Roles),
		securityPrincipal.WithPermissions(claims.Permissions),
		securityPrincipal.WithScopes(claims.Scopes),
		securityPrincipal.WithClaims(claims),
	)

	// 5. Issue a new credential (access token + new refresh token).
	// This automatically handles generating new IDs, expiration times, etc.
	return a.CreateCredential(ctx, p)
}

// Revoke invalidates the given credential.
func (a *Authenticator) Revoke(ctx context.Context, cred security.Credential) error {
	if a.cache == nil {
		a.log.WithContext(ctx).Warn("Cache is not configured, cannot revoke token.")
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

	claims, err := a.parseAndValidateToken(ctx, tokenStr, true)
	if err != nil {
		return err
	}

	if claims.ID == "" {
		return securityv1.ErrorClaimsInvalid("missing 'jti' claim for revocation")
	}
	if claims.ExpiresAt == nil {
		return securityv1.ErrorClaimsInvalid("missing or invalid 'exp' claim for revocation")
	}

	remainingTTL := time.Until(claims.ExpiresAt.Time)
	if remainingTTL <= 0 {
		a.log.WithContext(ctx).Debugf("Token with ID %s is already expired, no need to revoke.", claims.ID)
		return nil
	}

	if err := a.cache.Store(ctx, revocationKey(claims.ID), remainingTTL); err != nil {
		a.log.WithContext(ctx).Errorf("Failed to revoke token with ID %s in cache: %v", claims.ID, err)
		return securityv1.ErrorTokenInvalid("failed to revoke token in cache: %v", err)
	}
	a.log.WithContext(ctx).Infof("Token with ID %s successfully revoked.", claims.ID)
	return nil
}

// isTokenRevoked checks if a token has been revoked.
func (a *Authenticator) isTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	isRevoked, err := a.cache.Exist(ctx, revocationKey(tokenID))
	if err != nil {
		a.log.WithContext(ctx).Errorf("Error checking revocation status for token ID %s: %v", tokenID, err)
		return false, err
	}
	return isRevoked, nil
}

// parseAndValidateToken parses a JWT string and validates its claims.
func (a *Authenticator) parseAndValidateToken(ctx context.Context, tokenStr string, skipExpCheck bool) (*Claims, error) {
	claims := &Claims{}
	parserOpts := []jwtv5.ParserOption{
		jwtv5.WithIssuer(a.issuer),
		jwtv5.WithTimeFunc(a.clock),
	}
	if !a.skipAudienceCheck {
		parserOpts = append(parserOpts, jwtv5.WithAudience(a.audience...))
	}

	_, err := jwtv5.ParseWithClaims(tokenStr, claims, a.keyFunc, parserOpts...)
	if err != nil {
		if skipExpCheck && errors.Is(err, jwtv5.ErrTokenExpired) {
			a.log.WithContext(ctx).Debugf("Token expired but expiration check was skipped.")
			return claims, nil
		}
		a.log.WithContext(ctx).Debugf("Token parsing or validation failed: %v", err)
		return nil, mapJWTError(err)
	}

	// No need to check parsedToken.Valid as the parser options handle all validations.
	// If err is nil, the token is valid.
	a.log.WithContext(ctx).Debug("Token is valid.")
	return claims, nil
}

// signToken creates and signs a JWT string for the given claims.
func (a *Authenticator) signToken(ctx context.Context, claims jwtv5.Claims) (string, error) {
	token := jwtv5.NewWithClaims(a.signingMethod, claims)
	key, err := a.keyFunc(token)
	if err != nil {
		a.log.WithContext(ctx).Errorf("Failed to get signing key for token: %v", err)
		return "", securityv1.ErrorTokenSignFailed("failed to get signing key: %v", err)
	}
	signedString, err := token.SignedString(key)
	if err != nil {
		a.log.WithContext(ctx).Errorf("Failed to sign token: %v", err)
		return "", securityv1.ErrorTokenSignFailed("failed to sign token: %v", err)
	}
	return signedString, nil
}

// revocationKey creates a standard key for storing revocation status in the cache.
func revocationKey(tokenID string) string {
	return "jwt:revoked:" + tokenID
}

// mapJWTError maps errors from the jwt-go library to our internal error types.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwtv5.ErrTokenMalformed):
		return securityv1.ErrorTokenInvalid("token is malformed")
	case errors.Is(err, jwtv5.ErrTokenSignatureInvalid):
		return securityv1.ErrorTokenInvalid("token signature is invalid")
	case errors.Is(err, jwtv5.ErrTokenExpired):
		return securityv1.ErrorTokenExpired("token has expired")
	case errors.Is(err, jwtv5.ErrTokenNotValidYet):
		return securityv1.ErrorTokenInvalid("token not valid yet")
	case errors.Is(err, jwtv5.ErrTokenInvalidIssuer):
		return securityv1.ErrorClaimsInvalid("invalid issuer")
	case errors.Is(err, jwtv5.ErrTokenInvalidAudience):
		return securityv1.ErrorClaimsInvalid("invalid audience")
	default:
		return securityv1.ErrorTokenInvalid("unexpected token error: %v", err)
	}
}

// newWithOptions merges configurations from all sources.
func newWithOptions(cfg *authnv1.Authenticator, opts ...Option) (*Options, error) {
	finalOpts := FromOptions(opts...)
	jwtCfg := cfg.GetJwt()
	configProvided := jwtCfg != nil

	if finalOpts.signingMethod == nil && finalOpts.keyFunc == nil && configProvided && jwtCfg.SigningMethod != "" && jwtCfg.SigningKey != "" {
		signingMethod, keyFunc, err := configureKeys(jwtCfg.SigningMethod, jwtCfg.SigningKey)
		if err != nil {
			return nil, err
		}
		finalOpts.signingMethod = signingMethod
		finalOpts.keyFunc = keyFunc
	}

	if finalOpts.issuer == "" {
		if configProvided && jwtCfg.Issuer != "" {
			finalOpts.issuer = jwtCfg.Issuer
		} else {
			finalOpts.issuer = DefaultIssuer
		}
	}

	if len(finalOpts.audience) == 0 && configProvided && len(jwtCfg.Audience) > 0 {
		finalOpts.audience = jwtCfg.Audience
	}

	if finalOpts.accessTokenLifetime == 0 {
		if configProvided && jwtCfg.AccessTokenLifetime > 0 {
			finalOpts.accessTokenLifetime = time.Duration(jwtCfg.AccessTokenLifetime) * time.Second
		} else {
			finalOpts.accessTokenLifetime = DefaultAccessTokenTTL
		}
	}

	if finalOpts.refreshTokenLifetime == 0 {
		if configProvided && jwtCfg.RefreshTokenLifetime > 0 {
			finalOpts.refreshTokenLifetime = time.Duration(jwtCfg.RefreshTokenLifetime) * time.Second
		} else {
			finalOpts.refreshTokenLifetime = DefaultRefreshTokenTTL
		}
	}

	if finalOpts.clock == nil {
		finalOpts.clock = time.Now
	}
	if finalOpts.generateID == nil {
		finalOpts.generateID = uniuri.New
	}

	if finalOpts.signingMethod == nil || finalOpts.keyFunc == nil {
		return nil, fmt.Errorf("JWT signing method and key function must be configured")
	}

	return finalOpts, nil
}

// Interface compliance checks.
var (
	_ authn.Authenticator        = (*Authenticator)(nil)
	_ securityCredential.Creator = (*Authenticator)(nil)
	_ securityCredential.Revoker = (*Authenticator)(nil)
	_ securityCredential.Refresher = (*Authenticator)(nil)
	_ security.Claims            = (*Claims)(nil)
)
