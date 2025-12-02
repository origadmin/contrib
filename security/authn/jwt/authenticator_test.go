/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"context"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/credential"
	"github.com/origadmin/contrib/security/principal"
)

func TestAuthenticator(t *testing.T) {
	secret := "test-secret"
	issuer := "test-issuer"
	keyFunc := func(t *jwtv5.Token) (interface{}, error) {
		return []byte(secret), nil
	}

	auth, err := NewAuthenticator(
		&authnv1.Authenticator{
			Jwt: &jwtv1.Config{},
		},
		WithSigningMethod(jwtv5.SigningMethodHS256),
		WithKeyFunc(keyFunc),
		WithIssuer(issuer),
	)
	require.NoError(t, err, "Failed to create authenticator")

	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Subject:   "user123",
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			ID:        "token123",
		},
		Roles:       []string{"admin", "user"},
		Permissions: []string{"read", "write"},
		Scopes:      map[string]bool{"read": true, "write": false},
	}

	princ := principal.New(
		claims.Subject,
		principal.WithRoles(claims.Roles),
		principal.WithPermissions(claims.Permissions),
		principal.WithScopes(claims.Scopes),
		principal.WithClaims(claims),
	)

	t.Run("CreateCredential and Authenticate", func(t *testing.T) {
		resp, err := auth.(credential.Creator).CreateCredential(context.Background(), princ)
		require.NoError(t, err, "Failed to create credential")
		require.NotNil(t, resp, "Credential response is nil")

		tokenCred := resp.Payload().GetToken()
		require.NotNil(t, tokenCred, "TokenCredential should not be nil")
		accessToken := tokenCred.GetAccessToken()
		assert.NotEmpty(t, accessToken, "Access token is empty")

		bearerPayload := &securityv1.BearerCredential{Token: accessToken}
		bearerCred, err := credential.NewCredential(credential.BearerCredentialType, accessToken, bearerPayload, nil)
		require.NoError(t, err)

		authPrinc, err := auth.Authenticate(context.Background(), bearerCred)
		require.NoError(t, err, "Failed to authenticate token")
		require.NotNil(t, authPrinc, "Authenticated principal is nil")

		assert.Equal(t, princ.GetID(), authPrinc.GetID(), "Principal ID mismatch")
		assert.ElementsMatch(t, princ.GetRoles(), authPrinc.GetRoles(), "Principal roles mismatch")

		authClaims := authPrinc.GetClaims()
		require.NotNil(t, authClaims, "Authenticated claims are nil")

		jwtAuthClaims, ok := authClaims.(*Claims)
		require.True(t, ok, "Failed to type assert authenticated claims to *Claims")
		assert.Equal(t, issuer, jwtAuthClaims.Issuer, "Issuer mismatch")
		assert.Equal(t, "user123", jwtAuthClaims.Subject, "Subject mismatch")
	})

	t.Run("Authentication Failure", func(t *testing.T) {
		t.Run("Invalid Token", func(t *testing.T) {
			invalidPayload := &securityv1.BearerCredential{Token: "invalid-token-string"}
			invalidCred, _ := credential.NewCredential(credential.BearerCredentialType, "invalid-token-string", invalidPayload, nil)
			_, err := auth.Authenticate(context.Background(), invalidCred)
			assert.Error(t, err, "Expected an error for invalid token")
			assert.True(t, securityv1.IsTokenInvalid(err), "Expected InvalidToken error")
		})

		t.Run("Expired Token", func(t *testing.T) {
			// Manually create and sign an expired token
			expiredClaims := &Claims{
				RegisteredClaims: jwtv5.RegisteredClaims{
					Issuer:    issuer, // Must match the issuer the authenticator expects
					Subject:   "expired-user",
					ExpiresAt: jwtv5.NewNumericDate(now.Add(-time.Hour)), // Expired in the past
					IssuedAt:  jwtv5.NewNumericDate(now.Add(-2 * time.Hour)),
				},
			}
			token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, expiredClaims)
			expiredTokenString, err := token.SignedString([]byte(secret))
			require.NoError(t, err)

			// Create a credential with the expired token string
			expiredPayload := &securityv1.BearerCredential{Token: expiredTokenString}
			expiredCred, err := credential.NewCredential(credential.BearerCredentialType, expiredTokenString, expiredPayload, nil)
			require.NoError(t, err)

			// Authenticate and expect an error
			_, err = auth.Authenticate(context.Background(), expiredCred)
			assert.Error(t, err, "Expected an error for expired token")
			assert.True(t, securityv1.IsTokenExpired(err), "Expected TokenExpired error")
		})

		t.Run("Invalid Signature", func(t *testing.T) {
			otherAuth, _ := NewAuthenticator(
				&authnv1.Authenticator{
					Jwt: &jwtv1.Config{},
				},
				WithSigningMethod(jwtv5.SigningMethodHS256),
				WithKeyFunc(func(t *jwtv5.Token) (interface{}, error) { return []byte("different-secret"), nil }),
				WithIssuer(issuer),
			)
			resp, _ := otherAuth.(credential.Creator).CreateCredential(context.Background(), princ)
			tokenCred := resp.Payload().GetToken()
			invalidSigPayload := &securityv1.BearerCredential{Token: tokenCred.GetAccessToken()}
			invalidSigCred, _ := credential.NewCredential(credential.BearerCredentialType, tokenCred.GetAccessToken(), invalidSigPayload, nil)

			_, err := auth.Authenticate(context.Background(), invalidSigCred)
			assert.Error(t, err, "Expected an error for invalid signature")
			assert.True(t, securityv1.IsTokenInvalid(err), "Expected InvalidToken error for signature mismatch")
		})
	})
}

func TestPrincipalIntegration(t *testing.T) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "user123",
			Audience:  jwtv5.ClaimStrings{"test-audience"},
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			ID:        "token123",
		},
		Roles:       []string{"admin", "user"},
		Permissions: []string{"read", "write"},
		Scopes:      map[string]bool{"read": true, "write": false},
	}

	princ := principal.New(
		claims.Subject,
		principal.WithRoles(claims.Roles),
		principal.WithPermissions(claims.Permissions),
		principal.WithScopes(claims.Scopes),
		principal.WithClaims(claims),
	)

	t.Run("Principal Claims Access", func(t *testing.T) {
		pClaims := princ.GetClaims()
		require.NotNil(t, pClaims, "Principal claims should not be nil")

		sub, ok := pClaims.GetString("sub")
		assert.True(t, ok)
		assert.Equal(t, "user123", sub)

		roles, ok := pClaims.GetStringSlice("roles")
		assert.True(t, ok)
		assert.ElementsMatch(t, []string{"admin", "user"}, roles)
	})

	t.Run("Interface Compatibility", func(t *testing.T) {
		var _ security.Claims = (*Claims)(nil)
		var _ security.Claims = princ.GetClaims()
	})

	t.Run("Export and Import Principal", func(t *testing.T) {
		protoPrinc := princ.Export()
		require.NotNil(t, protoPrinc)

		importedPrinc, err := principal.FromProto(protoPrinc)
		require.NoError(t, err)

		assert.Equal(t, princ.GetID(), importedPrinc.GetID())
		assert.ElementsMatch(t, princ.GetRoles(), importedPrinc.GetRoles())

		importedClaims := importedPrinc.GetClaims()
		require.NotNil(t, importedClaims)

		sub, ok := importedClaims.GetString("sub")
		assert.True(t, ok)
		assert.Equal(t, "user123", sub)

		_, ok = importedClaims.(*Claims)
		assert.False(t, ok, "Type assertion to *Claims should fail after FromProto, this is expected.")
	})
}

// mockCache is a simple in-memory cache for testing revocation.
type mockCache struct {
	data map[string]time.Duration
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string]time.Duration),
	}
}

func (m *mockCache) Store(ctx context.Context, key string, ttl time.Duration) error {
	m.data[key] = ttl // In a real cache, this would store the key with an expiration. For mock, just store it.
	return nil
}

func (m *mockCache) Exist(ctx context.Context, key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func (m *mockCache) Remove(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockCache) Close(ctx context.Context) error {
	return nil
}

func TestAuthenticatorAdvancedFailures(t *testing.T) {
	secret := "test-secret"
	issuer := "test-issuer"
	audience := []string{"test-audience"}
	keyFunc := func(t *jwtv5.Token) (interface{}, error) {
		return []byte(secret), nil
	}

	// Authenticator with cache for revocation tests
	mockCache := newMockCache()
	authWithCache, err := NewAuthenticator(
		&authnv1.Authenticator{
			Jwt: &jwtv1.Config{},
		},
		WithSigningMethod(jwtv5.SigningMethodHS256),
		WithKeyFunc(keyFunc),
		WithIssuer(issuer),
		WithAudience(audience), // Use spread operator for []string
		WithCache(mockCache),   // Inject mock cache
	)
	require.NoError(t, err, "Failed to create authenticator with cache")

	// Authenticator without cache
	authNoCache, err := NewAuthenticator(
		&authnv1.Authenticator{
			Jwt: &jwtv1.Config{},
		},
		WithSigningMethod(jwtv5.SigningMethodHS256),
		WithKeyFunc(keyFunc),
		WithIssuer(issuer),
		WithAudience(audience),
	)
	require.NoError(t, err, "Failed to create authenticator without cache")

	now := time.Now()
	validClaims := &Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user123",
			Audience:  jwtv5.ClaimStrings(audience),
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now),
			ID:        "token123",
		},
	}
	validPrinc := principal.New(validClaims.Subject, principal.WithClaims(validClaims))

	t.Run("Token Not Valid Yet", func(t *testing.T) {
		nbfClaims := &Claims{
			RegisteredClaims: jwtv5.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "nbf-user",
				Audience:  jwtv5.ClaimStrings(audience),
				ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
				NotBefore: jwtv5.NewNumericDate(now.Add(time.Hour)), // Not valid until 1 hour from now
				IssuedAt:  jwtv5.NewNumericDate(now),
			},
		}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, nbfClaims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		bearerPayload := &securityv1.BearerCredential{Token: tokenString}
		bearerCred, err := credential.NewCredential(credential.BearerCredentialType, tokenString, bearerPayload, nil)
		require.NoError(t, err)

		_, err = authWithCache.Authenticate(context.Background(), bearerCred)
		assert.Error(t, err, "Expected an error for 'not valid yet' token")
		assert.True(t, securityv1.IsTokenInvalid(err), "Expected TokenInvalid error for 'not valid yet' token")
	})

	t.Run("Invalid Issuer", func(t *testing.T) {
		badIssuerClaims := &Claims{
			RegisteredClaims: jwtv5.RegisteredClaims{
				Issuer:    "bad-issuer", // Mismatch
				Subject:   "user123",
				Audience:  jwtv5.ClaimStrings(audience),
				ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwtv5.NewNumericDate(now),
				NotBefore: jwtv5.NewNumericDate(now),
			},
		}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, badIssuerClaims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		bearerPayload := &securityv1.BearerCredential{Token: tokenString}
		bearerCred, err := credential.NewCredential(credential.BearerCredentialType, tokenString, bearerPayload, nil)
		require.NoError(t, err)

		_, err = authWithCache.Authenticate(context.Background(), bearerCred)
		assert.Error(t, err, "Expected an error for invalid issuer")
		assert.True(t, securityv1.IsClaimsInvalid(err), "Expected ClaimsInvalid error for invalid issuer")
	})

	t.Run("Invalid Audience", func(t *testing.T) {
		badAudienceClaims := &Claims{
			RegisteredClaims: jwtv5.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "user123",
				Audience:  jwtv5.ClaimStrings{"bad-audience"}, // Mismatch
				ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwtv5.NewNumericDate(now),
				NotBefore: jwtv5.NewNumericDate(now),
			},
		}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, badAudienceClaims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		bearerPayload := &securityv1.BearerCredential{Token: tokenString}
		bearerCred, err := credential.NewCredential(credential.BearerCredentialType, tokenString, bearerPayload, nil)
		require.NoError(t, err)

		_, err = authWithCache.Authenticate(context.Background(), bearerCred)
		assert.Error(t, err, "Expected an error for invalid audience")
		assert.True(t, securityv1.IsClaimsInvalid(err), "Expected ClaimsInvalid error for invalid audience")
	})

	t.Run("Missing Subject Claim for Authentication", func(t *testing.T) {
		noSubClaims := &Claims{
			RegisteredClaims: jwtv5.RegisteredClaims{
				Issuer:    issuer,
				Audience:  jwtv5.ClaimStrings(audience),
				ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwtv5.NewNumericDate(now),
				NotBefore: jwtv5.NewNumericDate(now),
				ID:        "token-nosub",
			},
		}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, noSubClaims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		bearerPayload := &securityv1.BearerCredential{Token: tokenString}
		bearerCred, err := credential.NewCredential(credential.BearerCredentialType, tokenString, bearerPayload, nil)
		require.NoError(t, err)

		_, err = authWithCache.Authenticate(context.Background(), bearerCred)
		assert.Error(t, err, "Expected an error for missing subject claim")
		assert.True(t, securityv1.IsClaimsInvalid(err), "Expected ClaimsInvalid error for missing subject")
	})

	t.Run("Revocation Tests", func(t *testing.T) {
		t.Run("Successful Revocation", func(t *testing.T) {
			resp, err := authWithCache.(credential.Creator).CreateCredential(context.Background(), validPrinc)
			require.NoError(t, err)
			accessToken := resp.Payload().GetToken().GetAccessToken()

			bearerPayload := &securityv1.BearerCredential{Token: accessToken}
			bearerCred, err := credential.NewCredential(credential.BearerCredentialType, accessToken, bearerPayload, nil)
			require.NoError(t, err)

			// Revoke the token
			err = authWithCache.(credential.Revoker).Revoke(context.Background(), bearerCred)
			require.NoError(t, err, "Failed to revoke token")

			// Try to authenticate the revoked token
			_, err = authWithCache.Authenticate(context.Background(), bearerCred)
			assert.Error(t, err, "Expected error for revoked token authentication")
			assert.True(t, securityv1.IsTokenExpired(err), "Expected TokenExpired error for revoked token") // Revoked tokens are treated as expired
		})

		t.Run("Revoke without Cache Configured", func(t *testing.T) {
			resp, err := authNoCache.(credential.Creator).CreateCredential(context.Background(), validPrinc)
			require.NoError(t, err)
			accessToken := resp.Payload().GetToken().GetAccessToken()

			bearerPayload := &securityv1.BearerCredential{Token: accessToken}
			bearerCred, err := credential.NewCredential(credential.BearerCredentialType, accessToken, bearerPayload, nil)
			require.NoError(t, err)

			err = authNoCache.(credential.Revoker).Revoke(context.Background(), bearerCred)
			assert.Error(t, err, "Expected error when revoking without cache")
			assert.True(t, securityv1.IsSigningMethodUnsupported(err), "Expected SigningMethodUnsupported error")
		})

		t.Run("Revoke Token with Missing JTI", func(t *testing.T) {
			claimsNoID := &Claims{
				RegisteredClaims: jwtv5.RegisteredClaims{
					Issuer:    issuer,
					Subject:   "user-no-jti",
					Audience:  jwtv5.ClaimStrings(audience),
					ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
					IssuedAt:  jwtv5.NewNumericDate(now),
					NotBefore: jwtv5.NewNumericDate(now),
					ID:        "", // Missing JTI
				},
			}
			token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claimsNoID)
			tokenString, err := token.SignedString([]byte(secret))
			require.NoError(t, err)

			bearerPayload := &securityv1.BearerCredential{Token: tokenString}
			bearerCred, err := credential.NewCredential(credential.BearerCredentialType, tokenString, bearerPayload, nil)
			require.NoError(t, err)

			err = authWithCache.(credential.Revoker).Revoke(context.Background(), bearerCred)
			assert.Error(t, err, "Expected error for revoking token with missing JTI")
			assert.True(t, securityv1.IsClaimsInvalid(err), "Expected ClaimsInvalid error for missing JTI")
		})

		t.Run("Revoke Already Expired Token", func(t *testing.T) {
			expiredClaims := &Claims{
				RegisteredClaims: jwtv5.RegisteredClaims{
					Issuer:    issuer,
					Subject:   "expired-user-revoke",
					Audience:  jwtv5.ClaimStrings(audience),
					ExpiresAt: jwtv5.NewNumericDate(now.Add(-time.Hour)), // Expired
					IssuedAt:  jwtv5.NewNumericDate(now.Add(-2 * time.Hour)),
					ID:        "expired-jti",
				},
			}
			token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, expiredClaims)
			tokenString, err := token.SignedString([]byte(secret))
			require.NoError(t, err)

			bearerPayload := &securityv1.BearerCredential{Token: tokenString}
			bearerCred, err := credential.NewCredential(credential.BearerCredentialType, tokenString, bearerPayload, nil)
			require.NoError(t, err)

			err = authWithCache.(credential.Revoker).Revoke(context.Background(), bearerCred)
			assert.NoError(t, err, "Expected no error when revoking an already expired token")
		})

		t.Run("Revoke Malformed Token String", func(t *testing.T) {
			malformedToken := "this-is-not-a-jwt-token"
			bearerPayload := &securityv1.BearerCredential{Token: malformedToken}
			bearerCred, err := credential.NewCredential(credential.BearerCredentialType, malformedToken, bearerPayload, nil)
			require.NoError(t, err)

			err = authWithCache.(credential.Revoker).Revoke(context.Background(), bearerCred)
			assert.Error(t, err, "Expected error when revoking a malformed token string")
			assert.True(t, securityv1.IsTokenInvalid(err), "Expected TokenInvalid error for malformed token during revocation")
		})
	})

	t.Run("Supports Method", func(t *testing.T) {
		jwtCred, err := credential.NewCredential(credential.BearerCredentialType, "token", nil, nil)
		require.NoError(t, err)
		assert.True(t, authWithCache.Supports(jwtCred), "Authenticator should support JWT credential type")

		otherCred, err := credential.NewCredential("other-type", "token", nil, nil)
		require.NoError(t, err)
		assert.False(t, authWithCache.Supports(otherCred), "Authenticator should not support other credential types")
	})

	t.Run("NewAuthenticator Configuration Errors", func(t *testing.T) {
		t.Run("Missing Signing Method and Key Func", func(t *testing.T) {
			_, err := NewAuthenticator(&authnv1.Authenticator{Jwt: &jwtv1.Config{}})
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "JWT signing method and key function must be configured")
		})
	})
}
