/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package jwt provides a JWT-based implementation of the security interfaces.
package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/dchest/uniuri"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	authnv1 "github.com/origadmin/runtime/api/gen/go/config/security/authn/v1"
	securityv1 "github.com/origadmin/runtime/api/gen/go/config/security/v1"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/interfaces/security"
	"github.com/origadmin/runtime/log"
	"github.com/origadmin/runtime/security/authn"
	"github.com/origadmin/runtime/security/principal"
)

const (
	defaultIssuer          = "origadmin"
	defaultAccessTokenTTL  = 2 * time.Hour
	defaultRefreshTokenTTL = 7 * 24 * time.Hour
	claimRoles             = "roles"
	claimPermissions       = "permissions"
	claimScopes            = "scopes"
)

// Authenticator implements the security interfaces for JWT.
type Authenticator struct {
	keyFunc           jwtv5.Keyfunc
	signingMethod     jwtv5.SigningMethod
	issuer            string
	audience          []string
	accessTokenTTL    time.Duration
	refreshTokenTTL   time.Duration
	cache             cache.Cache
	generateID        func() string
	clock             jwtv5.TimeFunc
	skipAudienceCheck bool
}

// NewJWTAuthenticator creates a new JWT authenticator from the given configuration and options.
func NewJWTAuthenticator(cfg *authnv1.Authenticator, opts ...options.Option) (security.Authenticator, error) {
	jwtCfg := cfg.GetJwt()
	if jwtCfg == nil {
		return nil, errors.New("JWT configuration is missing")
	}
	o := FromOptions(opts)
	err := o.Apply(jwtCfg)
	if err != nil {
		return nil, err
	}

	signingMethod, keyFunc, err := configureKeys(jwtCfg)
	if err != nil {
		return nil, err
	}

	a := &Authenticator{
		keyFunc:           keyFunc,
		signingMethod:     signingMethod,
		issuer:            getIssuer(jwtCfg),
		audience:          jwtCfg.GetAudience(),
		accessTokenTTL:    getTTL(jwtCfg.GetExpirationAccess(), defaultAccessTokenTTL),
		refreshTokenTTL:   getTTL(jwtCfg.GetExpirationRefresh(), defaultRefreshTokenTTL),
		cache:             o.Cache,
		generateID:        uniuri.New,
		clock:             time.Now,
		skipAudienceCheck: len(jwtCfg.GetAudience()) == 0,
	}

	return a, nil
}

func init() {
	authn.RegisterAuthenticatorFactory("jwt", NewJWTAuthenticator)
}

// Authenticate validates the provided credential and returns a Principal if successful.
func (a *Authenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	if !a.Supports(cred) {
		return nil, securityv1.ErrUnsupportedCredentialType()
	}

	var bc securityv1.BearerCredential
	if err := cred.ParsedPayload(&bc); err != nil {
		return nil, securityv1.ErrInvalidCredential(err)
	}
	tokenStr := bc.GetToken()
	if tokenStr == "" {
		return nil, securityv1.ErrInvalidCredential(errors.New("token is empty"))
	}

	claims, err := a.parseAndValidateToken(tokenStr)
	if err != nil {
		return nil, err
	}

	if a.cache != nil {
		tokenID, ok := claims["jti"].(string)
		if !ok {
			return nil, securityv1.ErrInvalidCredential(errors.New("missing 'jti' claim for revocation check"))
		}
		isRevoked, err := a.isTokenRevoked(ctx, tokenID)
		if err != nil {
			log.Warnf("Failed to check token revocation status: %v", err)
			return nil, securityv1.ErrAuthentication(err, "token revocation check failed")
		}
		if isRevoked {
			return nil, securityv1.ErrTokenRevoked()
		}
	}

	subject, err := claims.GetSubject()
	if err != nil {
		return nil, securityv1.ErrInvalidCredential(err, "missing or invalid 'sub' claim")
	}

	roles, _ := claims[claimRoles]
	permissions, _ := claims[claimPermissions]
	scopes, _ := claims[claimScopes]

	principalClaims, err := principal.NewClaims(claims)
	if err != nil {
		return nil, securityv1.ErrAuthentication(err, "failed to create principal claims")
	}

	p := principal.New(
		subject,
		toStringSlice(roles),
		toStringSlice(permissions),
		toBoolMap(scopes),
		principalClaims,
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

	accessClaims := jwtv5.MapClaims{
		"iss":            a.issuer,
		"sub":            p.GetID(),
		"aud":            a.audience,
		"exp":            jwtv5.NewNumericDate(now.Add(a.accessTokenTTL)),
		"nbf":            jwtv5.NewNumericDate(now),
		"iat":            jwtv5.NewNumericDate(now),
		"jti":            accessTokenID,
		claimRoles:       p.GetRoles(),
		claimPermissions: p.GetPermissions(),
		claimScopes:      p.GetScopes(),
	}
	accessToken, err := a.signToken(accessClaims)
	if err != nil {
		return nil, securityv1.ErrAuthentication(err, "failed to sign access token")
	}

	refreshClaims := &jwtv5.RegisteredClaims{
		Issuer:    a.issuer,
		Subject:   p.GetID(),
		Audience:  a.audience,
		ExpiresAt: jwtv5.NewNumericDate(now.Add(a.refreshTokenTTL)),
		NotBefore: jwtv5.NewNumericDate(now),
		IssuedAt:  jwtv5.NewNumericDate(now),
		ID:        a.generateID(),
	}
	refreshToken, err := a.signToken(refreshClaims)
	if err != nil {
		return nil, securityv1.ErrAuthentication(err, "failed to sign refresh token")
	}

	return &securityv1.CredentialResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		ExpiresIn:        durationpb.New(a.accessTokenTTL),
		RefreshExpiresIn: durationpb.New(a.refreshTokenTTL),
		TokenType:        "Bearer",
		CreatedAt:        timestamppb.New(now),
	}, nil
}

// Revoke invalidates the given raw credential string.
func (a *Authenticator) Revoke(ctx context.Context, rawCredential string) error {
	if a.cache == nil {
		return securityv1.ErrUnsupportedOperation(errors.New("cache is not configured for token revocation"))
	}

	claims, err := a.parseAndValidateToken(rawCredential)
	if err != nil {
		return err
	}

	tokenID, ok := claims["jti"].(string)
	if !ok {
		return securityv1.ErrInvalidCredential(errors.New("missing 'jti' claim for revocation"))
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return securityv1.ErrInvalidCredential(err, "missing or invalid 'exp' claim")
	}

	remainingTTL := time.Until(expiresAt.Time)
	if remainingTTL <= 0 {
		return nil // Already expired
	}

	if err := a.cache.Set(ctx, revocationKey(tokenID), []byte("revoked"), remainingTTL); err != nil {
		return securityv1.ErrAuthentication(err, "failed to revoke token")
	}
	return nil
}

// isTokenRevoked checks if a token has been revoked.
func (a *Authenticator) isTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	val, err := a.cache.Get(ctx, revocationKey(tokenID))
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return string(val) == "revoked", nil
}

// parseAndValidateToken parses a JWT string and validates its claims.
func (a *Authenticator) parseAndValidateToken(tokenStr string) (jwtv5.MapClaims, error) {
	claims := jwtv5.MapClaims{}
	token, err := jwtv5.ParseWithClaims(tokenStr, claims, a.keyFunc,
		jwtv5.WithIssuer(a.issuer),
		jwtv5.WithTimeFunc(a.clock),
	)

	if err != nil {
		return nil, mapJWTError(err)
	}

	if !token.Valid {
		return nil, securityv1.ErrInvalidCredential(errors.New("token is invalid"))
	}

	if !a.skipAudienceCheck {
		aud, err := claims.GetAudience()
		if err != nil || !contains(aud, a.audience...) {
			return nil, securityv1.ErrInvalidCredential(errors.New("invalid audience"))
		}
	}

	return claims, nil
}

// signToken creates and signs a JWT string for the given claims.
func (a *Authenticator) signToken(claims jwtv5.Claims) (string, error) {
	token := jwtv5.NewWithClaims(a.signingMethod, claims)
	key, err := a.keyFunc(token)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}
	return token.SignedString(key)
}

// configureKeys determines the signing method and key function from the config.
func configureKeys(cfg *authnv1.JWT) (jwtv5.SigningMethod, jwtv5.Keyfunc, error) {
	alg := GetAlgorithmSigningMethod(cfg.GetAlgorithm())
	if alg == nil {
		return nil, nil, fmt.Errorf("unsupported JWT algorithm: %s", cfg.GetAlgorithm())
	}

	switch method := alg.(type) {
	case *jwtv5.SigningMethodHMAC:
		key := []byte(cfg.GetSigningKey())
		if len(key) == 0 {
			return nil, nil, errors.New("HMAC signing key is missing")
		}
		return method, func(t *jwtv5.Token) (interface{}, error) { return key, nil }, nil
	case *jwtv5.SigningMethodRSA, *jwtv5.SigningMethodRSAPSS:
		pubKey, err := parseRSAPublicKey(cfg.GetSigningKey())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		return method, func(t *jwtv5.Token) (interface{}, error) { return pubKey, nil }, nil
	default:
		return nil, nil, fmt.Errorf("unsupported signing method type: %T", method)
	}
}

// parseRSAPublicKey parses a PEM-encoded RSA public key.
func parseRSAPublicKey(keyData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
		}
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not an RSA public key")
	}
	return rsaKey, nil
}

// getTTL returns the duration from a protobuf Duration or a default value.
func getTTL(d *durationpb.Duration, defaultTTL time.Duration) time.Duration {
	if d != nil && d.IsValid() {
		return d.AsDuration()
	}
	return defaultTTL
}

// getIssuer returns the issuer from the config or a default value.
func getIssuer(cfg *authnv1.JWT) string {
	if cfg.GetIssuer() != "" {
		return cfg.GetIssuer()
	}
	return defaultIssuer
}

// revocationKey creates a standard key for storing revocation status in the cache.
func revocationKey(tokenID string) string {
	return fmt.Sprintf("jwt:revoked:%s", tokenID)
}

// mapJWTError maps errors from the jwt-go library to our internal error types.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwtv5.ErrTokenMalformed):
		return securityv1.ErrInvalidCredential(err, "token is malformed")
	case errors.Is(err, jwtv5.ErrTokenSignatureInvalid):
		return securityv1.ErrInvalidCredential(err, "token signature is invalid")
	case errors.Is(err, jwtv5.ErrTokenExpired):
		return securityv1.ErrTokenExpired()
	case errors.Is(err, jwtv5.ErrTokenNotValidYet):
		return securityv1.ErrInvalidCredential(err, "token not valid yet")
	case errors.Is(err, jwtv5.ErrInvalidIssuer):
		return securityv1.ErrInvalidCredential(err, "invalid issuer")
	default:
		return securityv1.ErrAuthentication(err)
	}
}

// Helper functions for type conversion
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	if s, ok := v.([]string); ok {
		return s
	}
	if i, ok := v.([]interface{}); ok {
		s := make([]string, 0, len(i))
		for _, val := range i {
			if str, ok := val.(string); ok {
				s = append(s, str)
			}
		}
		return s
	}
	return nil
}

func toBoolMap(v interface{}) map[string]bool {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]bool); ok {
		return m
	}
	if i, ok := v.(map[string]interface{}); ok {
		m := make(map[string]bool)
		for key, val := range i {
			if b, ok := val.(bool); ok {
				m[key] = b
			}
		}
		return m
	}
	return nil
}

func contains(slice []string, values ...string) bool {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	for _, s := range slice {
		if _, ok := set[s]; ok {
			return true
		}
	}
	return false
}

// Interface compliance checks.
var _ security.Authenticator = (*Authenticator)(nil)
var _ security.CredentialCreator = (*Authenticator)(nil)
var _ security.CredentialRevoker = (*Authenticator)(nil)
