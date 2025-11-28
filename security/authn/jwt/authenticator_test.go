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
		claims.Roles,
		claims.Permissions,
		claims.Scopes,
		claims,
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
		claims.Roles,
		claims.Permissions,
		claims.Scopes,
		claims,
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
