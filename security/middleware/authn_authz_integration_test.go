//go:build integration
// +build integration

package middleware_test

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
	securityifaces "github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	jwtAuthn "github.com/origadmin/contrib/security/authn/jwt"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin"
	"github.com/origadmin/contrib/security/middleware"
	"github.com/origadmin/contrib/security/principal"
)

// --- Test Fixture Setup ---

type testFixture struct {
	t                *testing.T
	jwtAuthenticator authn.Authenticator
	casbinAuthorizer authz.Authorizer
	mwFactory        *middleware.Factory
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
p, user123, /documents.Service/Edit, create
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
		mwFactory:        middleware.NewFactory(), // Defaults to Kratos propagation
	}
}

// --- Mocks and Helpers ---

type mockHeaderCarrier http.Header

func (m mockHeaderCarrier) Get(key string) string { return http.Header(m).Get(key) }
func (m mockHeaderCarrier) Set(key, value string) { http.Header(m).Set(key, value) }
func (m mockHeaderCarrier) Add(key, value string) { http.Header(m).Add(key, value) }
func (m mockHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
func (m mockHeaderCarrier) Values(key string) []string { return http.Header(m)[key] }

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
			errCheck:  securityv1.IsTokenInvalid,
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
			errCheck:  securityv1.IsTokenInvalid, // Without a token, authn fails first.
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

			chain := fx.mwFactory.NewStandalone(fx.jwtAuthenticator, fx.casbinAuthorizer, nil, nil)
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

// TestCompleteGatewayClientServerFlow tests the full chain of Gateway -> Client -> Server.
func TestCompleteGatewayClientServerFlow(t *testing.T) {
	fx := newTestFixture(t)

	// Create the middleware functions from the factory
	gatewayMiddleware := fx.mwFactory.NewGateway(fx.jwtAuthenticator, nil)
	clientMiddleware := fx.mwFactory.NewClient()
	backendMiddleware := fx.mwFactory.NewBackend(fx.casbinAuthorizer, nil)

	t.Run("Complete flow: Gateway authenticates -> Client propagates -> Server authorizes", func(t *testing.T) {
		// === Step 1: Gateway handles a request from the outside world ===
		gatewayTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		token := generateJWTToken(t, fx.secret, "user123", []string{"editor"})
		gatewayTr.RequestHeader().Set("Authorization", "Bearer "+token)
		gatewayCtx := transport.NewServerContext(context.Background(), gatewayTr)

		var gatewayPrincipal securityifaces.Principal
		gatewayHandler := gatewayMiddleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Gateway should have principal in context after authn")
			gatewayPrincipal = p
			return "gateway authenticated", nil
		})

		_, err := gatewayHandler(gatewayCtx, nil)
		require.NoError(t, err, "Gateway authentication should succeed")
		require.NotNil(t, gatewayPrincipal, "Gateway should extract principal")

		// === Step 2: Gateway (as a client) calls the backend service ===
		backendServiceTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		clientCtx := transport.NewClientContext(principal.NewContext(context.Background(), gatewayPrincipal), backendServiceTr)

		clientHandler := clientMiddleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "client propagated", nil
		})

		_, err = clientHandler(clientCtx, nil)
		require.NoError(t, err, "Client propagation should succeed")

		// Verify principal was propagated to the transport header
		propagatedPrincipalHeader := backendServiceTr.RequestHeader().Get(principal.MetadataKey)
		require.NotEmpty(t, propagatedPrincipalHeader, "Client should propagate principal in header")

		// === Step 3: Backend Server handles the request from the Gateway ===
		serverCtx := transport.NewServerContext(context.Background(), backendServiceTr)

		serverHandler := backendMiddleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Server should have principal in context after propagation")
			assert.Equal(t, gatewayPrincipal.GetID(), p.GetID(), "Server principal ID should match gateway's")
			return "server authorized", nil
		})

		_, err = serverHandler(serverCtx, nil)
		require.NoError(t, err, "Server authorization should succeed")
	})

	t.Run("Complete flow with insufficient permissions", func(t *testing.T) {
		// Step 1: Gateway authenticates a user with insufficient roles
		gatewayTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		token := generateJWTToken(t, fx.secret, "user456", []string{"user"}) // 'user' cannot 'create'
		gatewayTr.RequestHeader().Set("Authorization", "Bearer "+token)
		gatewayCtx := transport.NewServerContext(context.Background(), gatewayTr)

		var gatewayPrincipal securityifaces.Principal
		gatewayHandler := gatewayMiddleware(func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok)
			gatewayPrincipal = p
			return "gateway authenticated", nil
		})
		_, err := gatewayHandler(gatewayCtx, nil)
		require.NoError(t, err)

		// Step 2: Client propagates this principal
		backendServiceTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		clientCtx := transport.NewClientContext(principal.NewContext(context.Background(), gatewayPrincipal), backendServiceTr)
		clientHandler := clientMiddleware(func(ctx context.Context, req interface{}) (interface{}, error) { return "propagated", nil })
		_, err = clientHandler(clientCtx, nil)
		require.NoError(t, err)

		// Step 3: Server receives the request and denies authorization
		serverCtx := transport.NewServerContext(context.Background(), backendServiceTr)
		serverHandler := backendMiddleware(successHandler)

		_, err = serverHandler(serverCtx, nil)
		require.Error(t, err, "Server should deny due to insufficient permissions")
		assert.True(t, securityv1.IsPermissionDenied(err), "Should return PermissionDenied error")
	})
}
