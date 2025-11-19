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

	jwtv1 "github.com/origadmin/contrib/security/api/gen/go/config/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/security/api/gen/go/config/authn/v1"
	securityv1 "github.com/origadmin/contrib/security/api/gen/go/config/v1"
	"github.com/origadmin/runtime/interfaces/options"

	authnFactory "github.com/origadmin/contrib/security/authn"
	securityifaces "github.com/origadmin/contrib/security/security"
	securityCredential "github.com/origadmin/contrib/security/credential"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	securityToken "github.com/origadmin/contrib/security/token" // Assuming token is also moved
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

var _ securityToken.CacheStorage = (*mockCache)(nil)

func createTestProvider(t *testing.T, cache securityToken.CacheStorage) authnFactory.Provider {
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

	provider, err := NewProvider(cfg, WithCache(cache))
	require.NoError(t, err)
	require.NotNil(t, provider)
	return provider
}

func TestJWTProvider_Success(t *testing.T) {
	provider := createTestProvider(t, nil)
	auth, ok := provider.Authenticator()
	require.True(t, ok)
	creator, ok := provider.CredentialCreator()
	require.True(t, ok)

	// Create a valid token
	p := securityPrincipal.New("test-user", []string{"user"}, nil, nil, nil)
	resp, err := creator.CreateCredential(context.Background(), p)
	require.NoError(t, err)
	require.NotNil(t, resp)

	var tokenCred securityv1.TokenCredential
	require.NoError(t, resp.Payload().GetToken().UnmarshalTo(&tokenCred))
	accessToken := tokenCred.GetAccessToken()

	// Authenticate with the token
	cred, err := securityCredential.NewBearer(accessToken)
	require.NoError(t, err)

	authedPrincipal, err := auth.Authenticate(context.Background(), cred)
	require.NoError(t, err)
	assert.Equal(t, "test-user", authedPrincipal.GetID())
	assert.Equal(t, []string{"user"}, authedPrincipal.GetRoles())
}

func TestJWTProvider_FailureCases(t *testing.T) {
	provider := createTestProvider(t, nil)
	auth, ok := provider.Authenticator()
	require.True(t, ok)

	testCases := []struct {
		name        string
		token       string
		expectedErr func(error) bool
	}{
		{
			name:        "Malformed Token",
			token:       "this.is.not.a.jwt",
			expectedErr: securityv1.IsTokenInvalid,
		},
		{
			name: "Invalid Signature",
			token: func() string {
				claims := &Claims{RegisteredClaims: jwtv5.RegisteredClaims{Subject: "user"}}
				token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
				signed, _ := token.SignedString([]byte("wrong-secret"))
				return signed
			}(),
			expectedErr: securityv1.IsTokenInvalid,
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
			expectedErr: securityv1.IsTokenExpired,
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
			expectedErr: securityv1.IsClaimsInvalid,
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
			expectedErr: securityv1.IsClaimsInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := securityCredential.NewBearer(tc.token)
			require.NoError(t, err)
			_, err = auth.Authenticate(context.Background(), cred)
			require.Error(t, err)
			assert.True(t, tc.expectedErr(err), "error was not of expected type")
		})
	}
}

func TestJWTProvider_Revocation(t *testing.T) {
	cache := newMockCache()
	provider := createTestProvider(t, cache)
	auth, _ := provider.Authenticator()
	creator, _ := provider.CredentialCreator()
	revoker, _ := provider.CredentialRevoker()

	// 1. Create a token
	p := securityPrincipal.New("user-to-be-revoked", nil, nil, nil, nil)
	resp, err := creator.CreateCredential(context.Background(), p)
	require.NoError(t, err)
	var tokenCred securityv1.TokenCredential
	require.NoError(t, resp.Payload().GetToken().UnmarshalTo(&tokenCred))
	accessToken := tokenCred.GetAccessToken()

	// 2. Before revocation, authentication should succeed
	cred, _ := securityCredential.NewBearer(accessToken)
	_, err = auth.Authenticate(context.Background(), cred)
	assert.NoError(t, err)

	// 3. Revoke the token
	err = revoker.Revoke(context.Background(), cred)
	assert.NoError(t, err)

	// 4. After revocation, authentication should fail
	_, err = auth.Authenticate(context.Background(), cred)
	require.Error(t, err)
	assert.True(t, securityv1.IsTokenExpired(err))
}
