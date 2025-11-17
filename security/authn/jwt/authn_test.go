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
	"google.golang.org/protobuf/types/known/anypb"

	jwtv1 "github.com/origadmin/runtime/api/gen/go/config/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/runtime/api/gen/go/config/security/authn/v1"
	securityv1 "github.com/origadmin/runtime/api/gen/go/config/security/v1"
	"github.com/origadmin/runtime/interfaces/security"
	"github.com/origadmin/runtime/interfaces/security/token"
	"github.com/origadmin/runtime/security/credential"
	"github.com/origadmin/runtime/security/principal"
)

const (
	testSecretKey = "test-secret-key-for-hs256"
	testIssuer    = "test-issuer"
	testAudience  = "test-audience"
)

type mockCache struct {
	store map[string]bool
}

func newMockCache() *mockCache {
	return &mockCache{store: make(map[string]bool)}
}

func (m *mockCache) Store(ctx context.Context, key string, expiration time.Duration) error {
	m.store[key] = true
	return nil
}

func (m *mockCache) Exist(ctx context.Context, key string) (bool, error) {
	_, found := m.store[key]
	return found, nil
}

func (m *mockCache) Remove(ctx context.Context, key string) error {
	delete(m.store, key)
	return nil
}

func (m *mockCache) Close(ctx context.Context) error {
	return nil
}

var _ token.CacheStorage = (*mockCache)(nil)

func createTestAuthenticator(t *testing.T, cache token.CacheStorage) security.Authenticator {
	cfg := &authnv1.Authenticator{
		Name: "jwt",
		Authenticator: &authnv1.Authenticator_Jwt{
			Jwt: &authnv1.JWT{
				Config: &jwtv1.Config{
					SigningMethod: "HS256",
					SigningKey:    testSecretKey,
					Issuer:        testIssuer,
					Audience:      []string{testAudience},
				},
			},
		},
	}

	auth, err := NewJWTAuthenticator(cfg, WithCache(cache))
	require.NoError(t, err)
	require.NotNil(t, auth)
	return auth
}

func TestJWTAuthenticator_Success(t *testing.T) {
	auth := createTestAuthenticator(t, nil)

	// Create a valid token
	p := principal.New("test-user", []string{"user"}, nil, nil, nil)
	resp, err := auth.(security.CredentialCreator).CreateCredential(context.Background(), p)
	require.NoError(t, err)
	require.NotNil(t, resp)

	var tokenCred securityv1.TokenCredential
	require.NoError(t, resp.Payload().UnmarshalTo(&tokenCred))
	accessToken := tokenCred.GetAccessToken()

	// Authenticate with the token
	cred, err := credential.NewBearer(accessToken)
	require.NoError(t, err)

	authedPrincipal, err := auth.Authenticate(context.Background(), cred)
	require.NoError(t, err)
	assert.Equal(t, "test-user", authedPrincipal.GetID())
	assert.Equal(t, []string{"user"}, authedPrincipal.GetRoles())
}

func TestJWTAuthenticator_FailureCases(t *testing.T) {
	auth := createTestAuthenticator(t, nil)

	testCases := []struct {
		name        string
		token       string
		expectedErr string
	}{
		{
			name:        "Malformed Token",
			token:       "this.is.not.a.jwt",
			expectedErr: "token is malformed",
		},
		{
			name: "Invalid Signature",
			token: func() string {
				claims := &Claims{RegisteredClaims: jwtv5.RegisteredClaims{Subject: "user"}}
				token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte("wrong-secret"))
				return signed
			}(),
			expectedErr: "token signature is invalid",
		},
		{
			name: "Expired Token",
			token: func() string {
				claims := &Claims{RegisteredClaims: jwtv5.RegisteredClaims{
					Subject:   "user",
					ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(-1 * time.Hour)),
					Issuer:    testIssuer,
					Audience:  []string{testAudience},
				}}
				token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte(testSecretKey))
				return signed
			}(),
			expectedErr: "token has expired",
		},
		{
			name: "Invalid Issuer",
			token: func() string {
				claims := &Claims{RegisteredClaims: jwtv5.RegisteredClaims{
					Subject:   "user",
					ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(1 * time.Hour)),
					Issuer:    "wrong-issuer",
					Audience:  []string{testAudience},
				}}
				token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte(testSecretKey))
				return signed
			}(),
			expectedErr: "invalid issuer",
		},
		{
			name: "Invalid Audience",
			token: func() string {
				claims := &Claims{RegisteredClaims: jwtv5.RegisteredClaims{
					Subject:   "user",
					ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(1 * time.Hour)),
					Issuer:    testIssuer,
					Audience:  []string{"wrong-audience"},
				}}
				token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte(testSecretKey))
				return signed
			}(),
			expectedErr: "invalid audience",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := credential.NewBearer(tc.token)
			require.NoError(t, err)
			_, err = auth.Authenticate(context.Background(), cred)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestJWTAuthenticator_Revocation(t *testing.T) {
	cache := newMockCache()
	auth := createTestAuthenticator(t, cache)
	revoker, ok := auth.(security.CredentialRevoker)
	require.True(t, ok)

	// 1. Create a token
	p := principal.New("user-to-be-revoked", nil, nil, nil, nil)
	resp, err := auth.(security.CredentialCreator).CreateCredential(context.Background(), p)
	require.NoError(t, err)
	var tokenCred securityv1.TokenCredential
	require.NoError(t, resp.Payload().UnmarshalTo(&tokenCred))
	accessToken := tokenCred.GetAccessToken()

	// 2. Before revocation, authentication should succeed
	cred, _ := credential.NewBearer(accessToken)
	_, err = auth.Authenticate(context.Background(), cred)
	assert.NoError(t, err)

	// 3. Revoke the token
	err = revoker.Revoke(context.Background(), accessToken)
	assert.NoError(t, err)

	// 4. After revocation, authentication should fail
	_, err = auth.Authenticate(context.Background(), cred)
	require.Error(t, err)
	assert.True(t, securityv1.IsTokenExpired(err))
}

func TestNewCredentialResponse(t *testing.T) {
	payload := &securityv1.TokenCredential{AccessToken: "abc"}
	anyPayload, err := anypb.New(payload)
	require.NoError(t, err)

	resp := credential.NewResponse("jwt", anyPayload)
	require.NotNil(t, resp)
	assert.Equal(t, "jwt", resp.Type())

	var unpackedPayload securityv1.TokenCredential
	err = resp.Payload().UnmarshalTo(&unpackedPayload)
	require.NoError(t, err)
	assert.Equal(t, "abc", unpackedPayload.GetAccessToken())
}
