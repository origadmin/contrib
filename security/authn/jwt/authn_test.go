/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	middlewaresecurity "github.com/origadmin/runtime/agent/middleware/security"
	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	securityv1 "github.com/origadmin/runtime/gen/go/security/v1"
	"github.com/origadmin/runtime/interfaces/security"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	"github.com/go-kratos/kratos/v2/transport"
)

const (
	HeaderAuthorize = "Authorization"
)

type headerCarrier http.Header

func (hc headerCarrier) Get(key string) string { return http.Header(hc).Get(key) }

func (hc headerCarrier) Set(key string, value string) { http.Header(hc).Set(key, value) }

// Add append value to key-values pair.
func (hc headerCarrier) Add(key string, value string) {
	http.Header(hc).Add(key, value)
}

// Values returns a slice of values associated with the passed key.
func (hc headerCarrier) Values(key string) []string {
	return http.Header(hc).Values(key)
}

// Keys lists the keys stored in this carrier.
func (hc headerCarrier) Keys() []string {
	keys := make([]string, 0, len(hc))
	for k := range http.Header(hc) {
		keys = append(keys, k)
	}
	return keys
}

func newTokenHeader(headerKey string, token string) *headerCarrier {
	header := &headerCarrier{}
	header.Set(headerKey, fmt.Sprintf("%s %s", security.SchemeBearer.String(), token))
	return header
}

type Transport struct {
	kind      transport.Kind
	endpoint  string
	operation string
	reqHeader transport.Header
}

func (tr *Transport) Kind() transport.Kind {
	return tr.kind
}

func (tr *Transport) Endpoint() string {
	return tr.endpoint
}

func (tr *Transport) Operation() string {
	return tr.operation
}

func (tr *Transport) RequestHeader() transport.Header {
	return tr.reqHeader
}

func (tr *Transport) ReplyHeader() transport.Header {
	return nil
}

func generateJwtKey(key, sub string) string {
	mapClaims := jwtv5.MapClaims{}
	mapClaims["sub"] = sub
	claims := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, mapClaims)
	token, _ := claims.SignedString([]byte(key))
	return token
}

func TestServer(t *testing.T) {
	testKey := "testKey"

	token := generateJwtKey(testKey, "fly")

	tests := []struct {
		name      string
		ctx       context.Context
		alg       string
		exceptErr error
		key       string
	}{
		{
			name:      "normal",
			ctx:       transport.NewServerContext(context.Background(), &Transport{reqHeader: newTokenHeader(HeaderAuthorize, token)}),
			alg:       "HS256",
			exceptErr: nil,
			key:       testKey,
		},
		{
			name:      "miss token",
			ctx:       transport.NewServerContext(context.Background(), &Transport{reqHeader: headerCarrier{}}),
			alg:       "HS256",
			exceptErr: ErrBearerTokenMissing,
			key:       testKey,
		},
		{
			name: "token invalid",
			ctx: transport.NewServerContext(context.Background(), &Transport{
				reqHeader: newTokenHeader(HeaderAuthorize, "12313123"),
			}),
			alg:       "HS256",
			exceptErr: ErrInvalidToken,
			key:       testKey,
		},
		{
			name:      "method invalid",
			ctx:       transport.NewServerContext(context.Background(), &Transport{reqHeader: newTokenHeader(HeaderAuthorize, token)}),
			alg:       "ES384",
			exceptErr: ErrInvalidToken,
			key:       testKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testToken security.Claims
			next := func(ctx context.Context, _ interface{}) (interface{}, error) {
				testToken = middlewaresecurity.ClaimsFromContext(ctx)
				return "reply", nil
			}
			cfg := &configv1.Security{
				Authn: &configv1.AuthNConfig{
					Jwt: &configv1.AuthNConfig_JWTConfig{
						Algorithm:     test.alg,
						SigningKey:    testKey,
						OldSigningKey: "",
						ExpireTime:    nil,
						RefreshTime:   nil,
						CacheName:     "",
					},
				},
			}
			authenticator, err := NewAuthenticator(cfg)
			assert.Nil(t, err)
			server, err := middlewaresecurity.NewAuthN(cfg,
				middlewaresecurity.WithAuthenticator(authenticator),
				middlewaresecurity.WithSkipper())
			assert.Nil(t, err)
			handle := server(next)
			ctx := middlewaresecurity.WithSkipContextServer(test.ctx, middlewaresecurity.MetadataSecuritySkipKey)
			_, err = handle(ctx, test.name)
			assert.ErrorIs(t, err, test.exceptErr)
			if test.exceptErr == nil {
				if testToken == nil {
					t.Errorf("except testToken not nil, but got nil")
				}
			}
		})
	}
}

func TestClient(t *testing.T) {
	testKey := "testKey"

	tests := []struct {
		name        string
		expectError error
	}{
		{
			name:        "normal",
			expectError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := func(ctx context.Context, _ interface{}) (interface{}, error) {
				return "reply", nil
			}

			cfg := &configv1.Security{
				Authn: &configv1.AuthNConfig{
					Jwt: &configv1.AuthNConfig_JWTConfig{
						Algorithm:     "HS256",
						SigningKey:    testKey,
						OldSigningKey: "",
						ExpireTime:    nil,
						RefreshTime:   nil,
						CacheName:     "",
					},
				},
			}
			authenticator, err := NewAuthenticator(cfg)
			assert.Nil(t, err)

			auth, err := middlewaresecurity.NewAuthN(cfg,
				middlewaresecurity.WithAuthenticator(authenticator),
			)
			assert.Nil(t, err)

			// The client middleware should add the token, not expect it.
			// It should pull claims from the context.
			claims := &SecurityClaims{Claims: &securityv1.Claims{Sub: "fly"}}
			ctx := middlewaresecurity.NewContextWithClaims(context.Background(), claims)
			ctx = transport.NewClientContext(ctx, &Transport{reqHeader: &headerCarrier{}})

			handle := auth(next)
			_, err = handle(ctx, "ok")
			assert.ErrorIs(t, err, test.expectError)
		})
	}
}

func TestAuth(t *testing.T) {
	t.Parallel()
	//cache := memory.NewCache(memory.Selector{CleanupInterval: time.Second})
	//c:=security.WithCache(cache)
	//store := Memory
	ctx := context.Background()
	//middlewaresecurity.WithStorage(store)
	cfg := &configv1.Security{
		Authn: &configv1.AuthNConfig{
			Jwt: &configv1.AuthNConfig_JWTConfig{
				Algorithm:     "HS256",
				SigningKey:    "abc123",
				OldSigningKey: "",
				ExpireTime:    nil,
				RefreshTime:   nil,
				CacheName:     "",
			},
		},
	}
	jwtAuth, err := NewAuthenticator(cfg, WithCache(security.DefaultTokenCacheService()))
	assert.Nil(t, err)

	userID := "test"
	claims := &securityv1.Claims{
		Sub: userID,
		Iss: "test",
		Aud: []string{"test"},
		Exp: timestamppb.New(time.Now().Add(time.Hour)),
		Nbf: timestamppb.New(time.Now()),
		Iat: timestamppb.New(time.Now()),
		Jti: "not need",
		Scopes: map[string]bool{
			"test": true,
		},
	}
	token, err := jwtAuth.CreateToken(ctx, &SecurityClaims{Claims: claims})
	assert.Nil(t, err)
	assert.NotNil(t, token)

	// Authenticate
	resultClaims, err := jwtAuth.Authenticate(ctx, token)
	assert.Nil(t, err)
	assert.Equal(t, userID, resultClaims.GetSubject())

	// Verify
	ok, err := jwtAuth.Verify(ctx, token)
	assert.Nil(t, err)
	assert.True(t, ok)

	// Destroy
	err = jwtAuth.DestroyToken(ctx, token)
	assert.Nil(t, err)

	// Verify after destroy
	ok, err = jwtAuth.Verify(ctx, token)
	assert.NotNil(t, err)
	assert.False(t, ok)
	resultClaims, err = jwtAuth.Authenticate(ctx, token)
	assert.NotNil(t, err)
	assert.EqualError(t, err, ErrTokenNotFound.Error())
	assert.Empty(t, resultClaims)

	err = jwtAuth.Close(ctx)
	assert.Nil(t, err)
}
