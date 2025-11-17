/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package jwt provides a JWT-based implementation of the security interfaces.
package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/dchest/uniuri"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	authnv1 "github.com/origadmin/runtime/api/gen/go/config/security/authn/v1"
	securityv1 "github.com/origadmin/runtime/api/gen/go/config/security/v1"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/interfaces/security"
	"github.com/origadmin/runtime/interfaces/security/token"
	"github.com/origadmin/runtime/log"
	runtimeSecurity "github.com/origadmin/runtime/security"
	"github.com/origadmin/runtime/security/authn"
	"github.com/origadmin/runtime/security/principal"
)

const (
	defaultIssuer          = "origadmin"
	defaultAccessTokenTTL  = 2 * time.Hour
	defaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// Claims represents the JWT claims, including standard claims and custom ones.
type Claims struct {
	jwtv5.RegisteredClaims
	Roles       []string        `json:"roles,omitempty"`
	Permissions []string        `json:"permissions,omitempty"`
	Scopes      map[string]bool `json:"scopes,omitempty"`
}

func (c *Claims) Get(key string) (interface{}, bool) {
	switch key {
	case "roles":
		return c.Roles, true
	case "permissions":
		return c.Permissions, true
	case "scopes":
		return c.Scopes, true
	default:
		return nil, false
	}
}

func (c *Claims) GetString(key string) (string, bool) {
	if val, ok := c.Get(key); ok {
		if str, ok := val.(string); ok {
			return str, true
		}
	}
	return "", false
}

func (c *Claims) GetInt64(key string) (int64, bool) {
	if val, ok := c.Get(key); ok {
		if i, ok := val.(int64); ok {
			return i, true
		}
	}
	return 0, false
}

func (c *Claims) GetFloat64(key string) (float64, bool) {
	if val, ok := c.Get(key); ok {
		if f, ok := val.(float64); ok {
			return f, true
		}
	}
	return 0, false
}

func (c *Claims) GetBool(key string) (bool, bool) {
	if val, ok := c.Get(key); ok {
		if b, ok := val.(bool); ok {
			return b, true
		}
	}
	return false, false
}

func (c *Claims) GetStringSlice(key string) ([]string, bool) {
	if val, ok := c.Get(key); ok {
		if s, ok := val.([]string); ok {
			return s, true
		}
	}
	return nil, false
}

func (c *Claims) GetMap(key string) (map[string]string, bool) {
	if val, ok := c.Get(key); ok {
		if m, ok := val.(map[string]string); ok {
			return m, true
		}
	}
	return nil, false
}

func (c *Claims) Export() map[string]*structpb.Value {
	data, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	st, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return st.GetFields()
}

// Authenticator implements the security interfaces for JWT.
type Authenticator struct {
	keyFunc              jwtv5.Keyfunc
	signingMethod        jwtv5.SigningMethod
	issuer               string
	audience             []string
	accessTokenLifetime  time.Duration
	refreshTokenLifetime time.Duration
	cache                token.CacheStorage
	generateID           func() string
	clock                func() time.Time
	skipAudienceCheck    bool
}

// NewJWTAuthenticator creates a new JWT authenticator from the given configuration and options.
func NewJWTAuthenticator(cfg *authnv1.Authenticator, opts ...options.Option) (security.Authenticator, error) {
	jwtCfg := cfg.GetJwt()
	if jwtCfg == nil {
		return nil, runtimeSecurity.ErrInvalidArgument(nil, "JWT configuration is missing")
	}
	o := FromOptions(opts...)
	if err := o.Apply(jwtCfg); err != nil {
		return nil, err
	}

	a := &Authenticator{
		keyFunc:              o.keyFunc,
		signingMethod:        o.signingMethod,
		issuer:               o.issuer,
		audience:             o.audience,
		accessTokenLifetime:  o.accessTokenLifetime,
		refreshTokenLifetime: o.refreshTokenLifetime,
		cache:                o.cache,
		generateID:           uniuri.New,
		clock:                time.Now,
		skipAudienceCheck:    len(o.audience) == 0,
	}

	return a, nil
}

func init() {
	authn.RegisterAuthenticatorFactory("jwt", NewJWTAuthenticator)
}

// Authenticate validates the provided credential and returns a Principal if successful.
func (a *Authenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	if !a.Supports(cred) {
		return nil, runtimeSecurity.ErrUnsupportedCredentialType()
	}

	var bc securityv1.BearerCredential
	if err := cred.ParsedPayload(&bc); err != nil {
		return nil, runtimeSecurity.ErrInvalidCredential(err)
	}
	tokenStr := bc.GetToken()
	if tokenStr == "" {
		return nil, runtimeSecurity.ErrInvalidCredential(nil, "token is empty")
	}

	claims, err := a.parseAndValidateToken(tokenStr)
	if err != nil {
		return nil, err
	}

	if a.cache != nil {
		if claims.ID == "" {
			return nil, runtimeSecurity.ErrInvalidCredential(nil, "missing 'jti' claim for revocation check")
		}
		isRevoked, err := a.isTokenRevoked(ctx, claims.ID)
		if err != nil {
			log.Warnf("Failed to check token revocation status: %v", err)
			return nil, runtimeSecurity.ErrAuthentication(err, "token revocation check failed")
		}
		if isRevoked {
			return nil, runtimeSecurity.ErrTokenRevoked()
		}
	}

	if claims.Subject == "" {
		return nil, runtimeSecurity.ErrInvalidCredential(nil, "missing or invalid 'sub' claim")
	}

	p := principal.New(
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
		return nil, runtimeSecurity.ErrAuthentication(err, "failed to sign access token")
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
		return nil, runtimeSecurity.ErrAuthentication(err, "failed to sign refresh token")
	}

	tokenCred := &securityv1.TokenCredential{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(a.accessTokenLifetime.Seconds()),
		TokenType:    "Bearer",
	}

	anyPayload, err := anypb.New(tokenCred)
	if err != nil {
		return nil, runtimeSecurity.ErrInternal(err, "failed to marshal token credential")
	}

	return runtimeSecurity.NewCredentialResponse("jwt", anyPayload), nil
}

// Revoke invalidates the given raw credential string.
func (a *Authenticator) Revoke(ctx context.Context, rawCredential string) error {
	if a.cache == nil {
		return runtimeSecurity.ErrUnsupportedOperation(nil, "cache is not configured for token revocation")
	}

	claims, err := a.parseAndValidateToken(rawCredential)
	if err != nil {
		return err
	}

	if claims.ID == "" {
		return runtimeSecurity.ErrInvalidCredential(nil, "missing 'jti' claim for revocation")
	}

	if claims.ExpiresAt == nil {
		return runtimeSecurity.ErrInvalidCredential(nil, "missing or invalid 'exp' claim")
	}

	remainingTTL := time.Until(claims.ExpiresAt.Time)
	if remainingTTL <= 0 {
		return nil // Already expired
	}

	if err := a.cache.Store(ctx, revocationKey(claims.ID), remainingTTL); err != nil {
		return runtimeSecurity.ErrAuthentication(err, "failed to revoke token")
	}
	return nil
}

// isTokenRevoked checks if a token has been revoked.
func (a *Authenticator) isTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	return a.cache.Exist(ctx, revocationKey(tokenID))
}

// parseAndValidateToken parses a JWT string and validates its claims.
func (a *Authenticator) parseAndValidateToken(tokenStr string) (*Claims, error) {
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
		return nil, mapJWTError(err)
	}

	if !parsedToken.Valid {
		return nil, runtimeSecurity.ErrInvalidCredential(nil, "token is invalid")
	}

	return claims, nil
}

// signToken creates and signs a JWT string for the given claims.
func (a *Authenticator) signToken(claims jwtv5.Claims) (string, error) {
	token := jwtv5.NewWithClaims(a.signingMethod, claims)
	key, err := a.keyFunc(token)
	if err != nil {
		return "", runtimeSecurity.ErrInternal(err, "failed to get signing key")
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
		return runtimeSecurity.ErrInvalidCredential(err, "token is malformed")
	case errors.Is(err, jwtv5.ErrTokenSignatureInvalid):
		return runtimeSecurity.ErrInvalidCredential(err, "token signature is invalid")
	case errors.Is(err, jwtv5.ErrTokenExpired):
		return runtimeSecurity.ErrTokenExpired()
	case errors.Is(err, jwtv5.ErrTokenNotValidYet):
		return runtimeSecurity.ErrInvalidCredential(err, "token not valid yet")
	case errors.Is(err, jwtv5.ErrTokenInvalidIssuer):
		return runtimeSecurity.ErrInvalidCredential(err, "invalid issuer")
	case errors.Is(err, jwtv5.ErrTokenInvalidAudience):
		return runtimeSecurity.ErrInvalidCredential(err, "invalid audience")
	default:
		return runtimeSecurity.ErrAuthentication(err)
	}
}

// Interface compliance checks.
var (
	_ security.Authenticator     = (*Authenticator)(nil)
	_ security.CredentialCreator = (*Authenticator)(nil)
	_ security.CredentialRevoker = (*Authenticator)(nil)
	_ security.Claims            = (*Claims)(nil)
)
