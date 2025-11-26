//go:build integration
// +build integration

package middleware

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	kratosMiddleware "github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security/authn"
	jwtAuthn "github.com/origadmin/contrib/security/authn/jwt"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin"
	authnMiddleware "github.com/origadmin/contrib/security/middleware/authn"
	authzMiddleware "github.com/origadmin/contrib/security/middleware/authz"
	"github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/middleware"
)

// --- Test Fixture Setup ---

type testFixture struct {
	t                *testing.T
	jwtAuthenticator authn.Authenticator
	casbinAuthorizer authz.Authorizer
	authnMiddleware  *authnMiddleware.Middleware
	authzMiddleware  *authzMiddleware.Middleware
	secret           string
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	const testSecret = "test-secret-key-for-refactored-test"
	const casbinModelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	const casbinPolicyText = `
p, alice, /admin.Service/GetData, read
p, bob, /public.Service/GetInfo, read
p, editor, /documents.Service/Edit, create
p, user, /documents.Service/View, read
`

	jwtAuth, err := jwtAuthn.NewAuthenticator(&authnv1.Authenticator{
		Type: "jwt",
		Jwt: &jwtv1.Config{
			SigningMethod: "HS256",
			SigningKey:    testSecret,
			Issuer:        "test-issuer",
		},
	})
	require.NoError(t, err)

	m, err := model.NewModelFromString(casbinModelText)
	require.NoError(t, err)
	sa := stringadapter.NewAdapter(casbinPolicyText)

	casbinAuthz, err := casbin.NewAuthorizer(
		&authzv1.Authorizer{Type: authz.Casbin},
		casbin.WithModel(m),
		casbin.WithPolicyAdapter(sa),
	)
	require.NoError(t, err)

	return &testFixture{
		t:                t,
		secret:           testSecret,
		jwtAuthenticator: jwtAuth,
		casbinAuthorizer: casbinAuthz,
		authnMiddleware:  authnMiddleware.NewAuthNMiddleware(jwtAuth),
		authzMiddleware:  authzMiddleware.NewAuthZMiddleware(casbinAuthz),
	}
}

// --- Mocks and Helpers ---

type mockHeaderCarrier http.Header

func (m mockHeaderCarrier) Get(key string) string {
	return http.Header(m).Get(key)
}
func (m mockHeaderCarrier) Set(key string, value string) {
	http.Header(m).Set(key, value)
}
func (m mockHeaderCarrier) Add(key string, value string) {
	http.Header(m).Add(key, value)
}
func (m mockHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
func (m mockHeaderCarrier) Values(key string) []string {
	return http.Header(m)[key]
}

type mockTransport struct {
	operation string
	req       *http.Request
}

func newMockTransport(t *testing.T, method, op string) *mockTransport {
	req, err := http.NewRequest(method, op, nil)
	require.NoError(t, err)
	return &mockTransport{
		operation: op,
		req:       req,
	}
}

func (m *mockTransport) Kind() transport.Kind            { return transport.KindHTTP }
func (m *mockTransport) Endpoint() string                { return "" }
func (m *mockTransport) Operation() string               { return m.operation }
func (m *mockTransport) RequestHeader() transport.Header { return mockHeaderCarrier(m.req.Header) }
func (m *mockTransport) ReplyHeader() transport.Header   { return mockHeaderCarrier(m.req.Header) }
func (m *mockTransport) Request() *http.Request          { return m.req }
func (m *mockTransport) PathTemplate() string            { return m.operation }

var _ kratoshttp.Transporter = (*mockTransport)(nil)

func generateJWTToken(t *testing.T, secret string, userID string, roles []string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"roles": roles,
		"iss":   "test-issuer",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return tokenString
}

var successHandler = func(ctx context.Context, req interface{}) (interface{}, error) {
	return "success", nil
}

// --- Test Scenarios ---

func TestStandaloneFlow(t *testing.T) {
	fx := newTestFixture(t)

	testCases := []struct {
		name        string
		tokenUserID string
		tokenRoles  []string
		token       string
		operation   string
		expectErr   bool
		errCheck    func(err error) bool
	}{
		{
			name:        "Successful Authn and Authz",
			tokenUserID: "alice",
			tokenRoles:  []string{"admin"},
			operation:   "/admin.Service/GetData",
			expectErr:   false,
		},
		{
			name:      "Failed Authn (Invalid Token)",
			token:     "invalid-token",
			operation: "/admin.Service/GetData",
			expectErr: true,
			errCheck:  securityv1.IsCredentialsInvalid,
		},
		{
			name:        "Successful Authn, Failed Authz",
			tokenUserID: "bob",
			tokenRoles:  []string{"user"},
			operation:   "/admin.Service/GetData", // bob cannot 'read' admin data
			expectErr:   true,
			errCheck:    securityv1.IsPermissionDenied,
		},
		{
			name:      "No Token, Access Denied",
			token:     "",
			operation: "/admin.Service/GetData",
			expectErr: true,
			errCheck:  securityv1.IsCredentialsInvalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newMockTransport(t, "GET", tc.operation)
			token := tc.token
			if token == "" && tc.tokenUserID != "" {
				token = generateJWTToken(t, fx.secret, tc.tokenUserID, tc.tokenRoles)
			}
			if token != "" {
				tr.RequestHeader().Set("Authorization", "Bearer "+token)
			}

			ctx := transport.NewServerContext(context.Background(), tr)

			var capturedCtx context.Context
			captureHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
				capturedCtx = ctx
				return successHandler(ctx, req)
			}

			chain := kratosMiddleware.Chain(fx.authnMiddleware.Server(), fx.authzMiddleware.Server())
			finalHandler := chain(captureHandler)
			_, err := finalHandler(ctx, nil)

			if tc.expectErr {
				require.Error(t, err, "Expected an error")
				if tc.errCheck != nil {
					assert.True(t, tc.errCheck(err), "Error type mismatch, got: %v", err)
				}
			} else {
				require.NoError(t, err, "Expected no error")
				p, ok := principal.FromContext(capturedCtx)
				require.True(t, ok, "Principal should be in context on success")
				assert.Equal(t, tc.tokenUserID, p.GetID())
			}
		})
	}
}

func principalFromHeaderMiddleware() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if _, ok := principal.FromContext(ctx); ok {
				return handler(ctx, req) // Principal already present
			}

			tr, ok := transport.FromServerContext(ctx)
			if !ok {
				return nil, securityv1.ErrorCredentialsInvalid("missing transport context")
			}

			encodedPrincipal := tr.RequestHeader().Get(principal.MetadataKey)
			if encodedPrincipal == "" {
				return handler(ctx, req)
			}

			p, err := principal.DecodePrincipal(encodedPrincipal)
			if err != nil {
				return nil, securityv1.ErrorCredentialsInvalid("invalid propagated principal: %v", err)
			}

			ctx = principal.NewContext(ctx, p)
			return handler(ctx, req)
		}
	}
}

func TestGatewayServerFlow(t *testing.T) {
	fx := newTestFixture(t)

	t.Run("Gateway authenticates and propagates, Server authorizes successfully", func(t *testing.T) {
		// --- Gateway Simulation ---
		gatewayTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		token := generateJWTToken(t, fx.secret, "user-id-123", []string{"editor"})
		gatewayTr.RequestHeader().Set("Authorization", "Bearer "+token)
		gatewayCtx := transport.NewServerContext(context.Background(), gatewayTr)

		gatewayAuthnHandler := fx.authnMiddleware.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {

			return "gateway processed", nil

		})
		_, err := gatewayAuthnHandler(gatewayCtx, nil)
		require.NoError(t, err)

		p_for_authz := principal.EmptyPrincipal("editor")
		backendServiceTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		clientCtx := transport.NewClientContext(principal.NewContext(context.Background(), p_for_authz), backendServiceTr)

		propagateHandler := fx.authnMiddleware.Client()(func(ctx context.Context, req interface{}) (interface{}, error) { return "propagated", nil })
		_, err = propagateHandler(clientCtx, nil)
		require.NoError(t, err)

		// --- Server Simulation ---
		serverMiddlewareChain := kratosMiddleware.Chain(principalFromHeaderMiddleware(), fx.authzMiddleware.Server())
		serverCtx := transport.NewServerContext(context.Background(), backendServiceTr)
		finalServerHandler := serverMiddlewareChain(successHandler)
		_, err = finalServerHandler(serverCtx, nil)

		require.NoError(t, err, "Server should authorize the valid propagated principal")
	})

	t.Run("Server denies request for insufficient permissions", func(t *testing.T) {
		gatewayP := principal.EmptyPrincipal("user")
		backendServiceTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		encodedP, err := principal.EncodePrincipal(gatewayP)
		require.NoError(t, err)
		backendServiceTr.RequestHeader().Set(principal.MetadataKey, encodedP)

		serverMiddlewareChain := kratosMiddleware.Chain(principalFromHeaderMiddleware(), fx.authzMiddleware.Server())
		serverCtx := transport.NewServerContext(context.Background(), backendServiceTr)
		finalServerHandler := serverMiddlewareChain(successHandler)
		_, err = finalServerHandler(serverCtx, nil)

		require.Error(t, err, "Server should deny for insufficient permissions")
		assert.True(t, securityv1.IsPermissionDenied(err), "Expected PermissionDenied error")
	})

	t.Run("Server denies request with missing propagated principal", func(t *testing.T) {
		backendServiceTr := newMockTransport(t, "GET", "/documents.Service/Edit")

		serverMiddlewareChain := kratosMiddleware.Chain(principalFromHeaderMiddleware(), fx.authzMiddleware.Server())
		serverCtx := transport.NewServerContext(context.Background(), backendServiceTr)
		finalServerHandler := serverMiddlewareChain(successHandler)
		_, err := finalServerHandler(serverCtx, nil)

		require.Error(t, err, "Server should deny request with missing principal")
		assert.True(t, securityv1.IsCredentialsInvalid(err), "Expected CredentialsInvalid error")
	})
}
