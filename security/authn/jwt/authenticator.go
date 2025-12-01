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

	uniuri "github.com/dchest/uniuri"
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

// NewAuthenticator creates a new JWT Provider from the given configuration and options.
func NewAuthenticator(cfg *authnv1.Authenticator, opts ...Option) (authn.Authenticator, error) {
	finalOpts, err := newWithOptions(cfg, opts...)
	if err != nil {
		return nil, err
	}

	// Initialize logger
	logger := log.FromOptions(opts) // Convert jwt.Option to options.Option
	helper := log.NewHelper(log.With(logger, "module", "security.authn.jwt"))

	auth := &Authenticator{
		Options:           finalOpts,
		skipAudienceCheck: len(finalOpts.audience) == 0, // Calculate derived state here
		log:               helper,
	}

	auth.log.Debugf("JWT Authenticator initialized with issuer: %s, audience: %v", auth.issuer, auth.audience)

	return auth, nil
}

// Authenticate validates the provided credential and returns a Principal if successful.
func (a *Authenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	a.log.Debugf("Attempting to authenticate credential type: %s", cred.Type())

	if !a.Supports(cred) {
		a.log.Warnf("Unsupported credential type: %s", cred.Type())
		return nil, securityv1.ErrorCredentialsInvalid("unsupported credential type: %s", cred.Type())
	}

	var bc securityv1.BearerCredential
	if err := cred.ParsedPayload(&bc); err != nil {
		a.log.Errorf("Failed to parse bearer credential payload: %v", err)
		return nil, securityv1.ErrorBearerTokenInvalid("failed to parse bearer credential: %v", err)
	}
	tokenStr := bc.GetToken()
	if tokenStr == "" {
		a.log.Warn("Token is empty in bearer credential")
		return nil, securityv1.ErrorTokenMissing("token is empty")
	}

	claims, err := a.parseAndValidateToken(tokenStr, false) // Full validation for authentication
	if err != nil {
		a.log.Errorf("Failed to parse and validate token: %v", err)
		return nil, err
	}
	a.log.Debugf("Token parsed successfully for subject: %s", claims.Subject)

	if a.cache != nil {
		if claims.ID == "" {
			a.log.Warn("Missing 'jti' claim for revocation check")
			return nil, securityv1.ErrorClaimsInvalid("missing 'jti' claim for revocation check")
		}
		isRevoked, err := a.isTokenRevoked(ctx, claims.ID)
		if err != nil {
			a.log.Warnf("Failed to check token revocation status for ID %s: %v", claims.ID, err)
			return nil, securityv1.ErrorTokenInvalid("token revocation check failed: %v", err)
		}
		if isRevoked {
			a.log.Warnf("Token with ID %s has been revoked", claims.ID)
			return nil, securityv1.ErrorTokenExpired("token has been revoked")
		}
		a.log.Debugf("Token with ID %s is not revoked", claims.ID)
	}

	if claims.Subject == "" {
		a.log.Warn("Missing or invalid 'sub' claim in token")
		return nil, securityv1.ErrorClaimsInvalid("missing or invalid 'sub' claim")
	}

	// Create Principal using the new functional options pattern.
	// The Authenticator's issuer is used as the Principal's domain.
	p := securityPrincipal.New(
		claims.Subject,
		a.issuer, // Use the Authenticator's issuer as the Principal's domain
		securityPrincipal.WithRoles(claims.Roles),
		securityPrincipal.WithPermissions(claims.Permissions),
		securityPrincipal.WithScopes(claims.Scopes),
		securityPrincipal.WithClaims(claims), // Pass the entire claims object
	)
	a.log.Debugf("Principal created for subject: %s, domain: %s", p.GetID(), p.GetDomain())

	return p, nil
}

// Supports returns true if this authenticator can handle the given credential.
func (a *Authenticator) Supports(cred security.Credential) bool {
	return cred.Type() == "jwt"
}

// CreateCredential issues a new credential for the given principal.
func (a *Authenticator) CreateCredential(ctx context.Context, p security.Principal) (security.CredentialResponse, error) {
	a.log.Debugf("Creating credential for principal ID: %s", p.GetID())
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
		a.log.Errorf("Failed to sign access token for principal %s: %v", p.GetID(), err)
		return nil, err
	}
	a.log.Debugf("Access token signed for principal %s, ID: %s", p.GetID(), accessTokenID)

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
		a.log.Errorf("Failed to sign refresh token for principal %s: %v", p.GetID(), err)
		return nil, err
	}
	a.log.Debugf("Refresh token signed for principal %s", p.GetID())

	tokenCred := &securityv1.TokenCredential{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(a.accessTokenLifetime.Seconds()),
		TokenType:    "Bearer",
	}

	payload := &securityv1.Payload{
		Token: tokenCred,
	}

	a.log.Debugf("Credential created for principal %s", p.GetID())
	return securityCredential.NewCredentialResponse(authn.JWT, payload, make(map[string][]string)), nil
}

// Revoke invalidates the given credential.
func (a *Authenticator) Revoke(ctx context.Context, cred security.Credential) error {
	a.log.Debugf("Attempting to revoke credential type: %s", cred.Type())

	if a.cache == nil {
		a.log.Warn("Cache is not configured for token revocation")
		return securityv1.ErrorSigningMethodUnsupported("cache is not configured for token revocation")
	}

	if !a.Supports(cred) {
		a.log.Warnf("Unsupported credential type for revocation: %s", cred.Type())
		return securityv1.ErrorCredentialsInvalid("unsupported credential type for revocation: %s", cred.Type())
	}

	var bc securityv1.BearerCredential
	if err := cred.ParsedPayload(&bc); err != nil {
		a.log.Errorf("Failed to parse bearer credential for revocation: %v", err)
		return securityv1.ErrorBearerTokenInvalid("failed to parse bearer credential for revocation: %v", err)
	}
	tokenStr := bc.GetToken()
	if tokenStr == "" {
		a.log.Warn("Token is empty for revocation")
		return securityv1.ErrorTokenMissing("token is empty for revocation")
	}

	// For revocation, we only need the claims, and we can ignore if the token is already expired.
	claims, err := a.parseAndValidateToken(tokenStr, true) // `true` to skip expiration check
	if err != nil {
		a.log.Errorf("Failed to parse and validate token for revocation: %v", err)
		// Any error other than expiration is still a problem (e.g., bad signature).
		return err
	}
	a.log.Debugf("Token parsed for revocation for ID: %s", claims.ID)

	if claims.ID == "" {
		a.log.Warn("Missing 'jti' claim for revocation")
		return securityv1.ErrorClaimsInvalid("missing 'jti' claim for revocation")
	}

	// We still need the expiration time to set a TTL on the revocation entry in the cache.
	if claims.ExpiresAt == nil {
		a.log.Warn("Missing or invalid 'exp' claim for revocation")
		return securityv1.ErrorClaimsInvalid("missing or invalid 'exp' claim for revocation")
	}

	remainingTTL := time.Until(claims.ExpiresAt.Time)
	if remainingTTL <= 0 {
		a.log.Debugf("Token with ID %s is already expired, no need to revoke", claims.ID)
		return nil // Already expired, no need to add to cache.
	}

	if err := a.cache.Store(ctx, revocationKey(claims.ID), remainingTTL); err != nil {
		a.log.Errorf("Failed to revoke token with ID %s in cache: %v", claims.ID, err)
		return securityv1.ErrorTokenInvalid("failed to revoke token in cache: %v", err)
	}
	a.log.Infof("Token with ID %s successfully revoked until %v", claims.ID, claims.ExpiresAt.Time)
	return nil
}

// isTokenRevoked checks if a token has been revoked.
func (a *Authenticator) isTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	isRevoked, err := a.cache.Exist(ctx, revocationKey(tokenID))
	if err != nil {
		a.log.Errorf("Error checking revocation status for token ID %s: %v", tokenID, err)
		return false, err
	}
	if isRevoked {
		a.log.Debugf("Token ID %s found in revocation list", tokenID)
	}
	return isRevoked, nil
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
			a.log.Debugf("Token expired but expiration check skipped for token: %s", tokenStr)
			// The token is expired, but the caller wants to proceed, so we return the parsed claims.
			// The claims are still populated even when this error occurs.
			return claims, nil
		}
		a.log.Errorf("Token parsing or validation failed for token: %s, error: %v", tokenStr, err)
		return nil, mapJWTError(err)
	}

	if !parsedToken.Valid {
		a.log.Warnf("Token is invalid: %s", tokenStr)
		return nil, securityv1.ErrorTokenInvalid("token is invalid")
	}
	a.log.Debug("Token is valid")

	return claims, nil
}

// signToken creates and signs a JWT string for the given claims.
func (a *Authenticator) signToken(claims jwtv5.Claims) (string, error) {
	token := jwtv5.NewWithClaims(a.signingMethod, claims)
	key, err := a.keyFunc(token)
	if err != nil {
		a.log.Errorf("Failed to get signing key for token: %v", err)
		return "", securityv1.ErrorTokenSignFailed("failed to get signing key: %v", err)
	}
	signedString, err := token.SignedString(key)
	if err != nil {
		a.log.Errorf("Failed to sign token: %v", err)
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

// newWithOptions merges configurations from all sources.
func newWithOptions(cfg *authnv1.Authenticator, opts ...Option) (*Options, error) {
	finalOpts := FromOptions(opts...)
	jwtCfg := cfg.GetJwt()          // Get jwtCfg here, it might be nil
	configProvided := jwtCfg != nil // Use a boolean flag to check if jwtCfg is provided

	// Configure signing method and key function from the config file.
	// Only apply if not already set by functional options.
	if finalOpts.signingMethod == nil && finalOpts.keyFunc == nil && configProvided && jwtCfg.SigningMethod != "" && jwtCfg.SigningKey != "" {
		signingMethod, keyFunc, err := configureKeys(jwtCfg.SigningMethod, jwtCfg.SigningKey)
		if err != nil {
			return nil, err
		}
		finalOpts.signingMethod = signingMethod
		finalOpts.keyFunc = keyFunc
	}

	// Set Issuer. Only apply if not already set by functional options.
	if finalOpts.issuer == "" {
		if configProvided && jwtCfg.Issuer != "" {
			finalOpts.issuer = jwtCfg.Issuer
		} else {
			finalOpts.issuer = DefaultIssuer
		}
	}

	// Set Audience. Only apply if not already set by functional options.
	if len(finalOpts.audience) == 0 && configProvided && len(jwtCfg.Audience) > 0 {
		finalOpts.audience = jwtCfg.Audience
	}

	// Set token TTLs. Only apply if not already set by functional options.
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

	// Set default clock and generateID if not provided by options
	if finalOpts.clock == nil {
		finalOpts.clock = time.Now
	}
	if finalOpts.generateID == nil {
		finalOpts.generateID = uniuri.New
	}

	// Final validation for required fields
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
	_ security.Claims            = (*Claims)(nil)
)
