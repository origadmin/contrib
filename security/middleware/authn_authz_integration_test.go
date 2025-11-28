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
	securityifaces "github.com/origadmin/contrib/security"
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

// TestCompleteGatewayClientServerFlow 测试完整的 Gateway -> Client -> Server 传递链路
func TestCompleteGatewayClientServerFlow(t *testing.T) {
	fx := newTestFixture(t)

	t.Run("Complete flow: Gateway authenticates -> Client propagates -> Server authorizes", func(t *testing.T) {
		// === Step 1: Gateway 处理客户端请求 ===
		// 模拟客户端发送请求到 Gateway
		gatewayTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		token := generateJWTToken(t, fx.secret, "user123", []string{"editor"})
		gatewayTr.RequestHeader().Set("Authorization", "Bearer "+token)
		gatewayCtx := transport.NewServerContext(context.Background(), gatewayTr)

		// Gateway 进行认证
		var gatewayPrincipal securityifaces.Principal
		gatewayAuthnHandler := fx.authnMiddleware.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			// 认证成功，提取 principal
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Gateway should have principal in context after authn")
			gatewayPrincipal = p
			assert.Equal(t, "user123", p.GetID())
			assert.Contains(t, p.GetRoles(), "editor")
			return "gateway authenticated", nil
		})

		_, err := gatewayAuthnHandler(gatewayCtx, nil)
		require.NoError(t, err, "Gateway authentication should succeed")
		require.NotNil(t, gatewayPrincipal, "Gateway should extract principal")

		// === Step 2: Client 传播认证信息到后端服务 ===
		// 模拟 Gateway 作为客户端调用后端服务
		backendServiceTr := newMockTransport(t, "POST", "/documents.Service/Edit")

		// 将 Gateway 认证后的 principal 放入客户端 context
		clientCtx := transport.NewClientContext(
			principal.NewContext(context.Background(), gatewayPrincipal),
			backendServiceTr,
		)

		// Client 中间件传播 principal
		clientPropagateHandler := fx.authnMiddleware.Client()(func(ctx context.Context, req interface{}) (interface{}, error) {
			// 验证 principal 是否被正确传播到 header
			encodedPrincipal := backendServiceTr.RequestHeader().Get(principal.MetadataKey)
			require.NotEmpty(t, encodedPrincipal, "Client should propagate principal in header")

			// 验证编码的 principal 可以正确解码
			decodedPrincipal, err := principal.DecodePrincipal(encodedPrincipal)
			require.NoError(t, err, "Should be able to decode propagated principal")
			assert.Equal(t, gatewayPrincipal.GetID(), decodedPrincipal.GetID())

			return "client propagated", nil
		})

		_, err = clientPropagateHandler(clientCtx, nil)
		require.NoError(t, err, "Client propagation should succeed")

		// === Step 3: Server 接收传播信息并进行授权 ===
		// 模拟后端服务接收请求
		serverTr := newMockTransport(t, "POST", "/documents.Service/Edit")

		// 将客户端传播的 principal header 复制到服务器 transport
		propagatedPrincipal := backendServiceTr.RequestHeader().Get(principal.MetadataKey)
		serverTr.RequestHeader().Set(principal.MetadataKey, propagatedPrincipal)
		serverCtx := transport.NewServerContext(context.Background(), serverTr)

		// Server 进行授权检查
		var serverPrincipal securityifaces.Principal
		serverAuthzHandler := kratosMiddleware.Chain(
			principalFromHeaderMiddleware(), // 首先从 header 解析 principal
			fx.authzMiddleware.Server(),     // 然后进行授权
		)(func(ctx context.Context, req interface{}) (interface{}, error) {
			// 验证 principal 是否正确传递到 server
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Server should have principal in context")
			serverPrincipal = p
			assert.Equal(t, "user123", p.GetID())
			assert.Contains(t, p.GetRoles(), "editor")
			return "server authorized", nil
		})

		_, err = serverAuthzHandler(serverCtx, nil)
		require.NoError(t, err, "Server authorization should succeed")
		require.NotNil(t, serverPrincipal, "Server should receive principal")

		// === 验证整个链路的完整性 ===
		assert.Equal(t, gatewayPrincipal.GetID(), serverPrincipal.GetID(), "Principal ID should be consistent across the chain")
		assert.Equal(t, gatewayPrincipal.GetRoles(), serverPrincipal.GetRoles(), "Principal roles should be consistent across the chain")
	})

	t.Run("Complete flow with insufficient permissions", func(t *testing.T) {
		// === Step 1: Gateway 认证成功（但权限不足） ===
		gatewayTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		token := generateJWTToken(t, fx.secret, "user456", []string{"user"}) // user 角色，不是 editor
		gatewayTr.RequestHeader().Set("Authorization", "Bearer "+token)
		gatewayCtx := transport.NewServerContext(context.Background(), gatewayTr)

		var gatewayPrincipal securityifaces.Principal
		gatewayAuthnHandler := fx.authnMiddleware.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok)
			gatewayPrincipal = p
			return "gateway authenticated", nil
		})

		_, err := gatewayAuthnHandler(gatewayCtx, nil)
		require.NoError(t, err)

		// === Step 2: Client 传播 ===
		backendServiceTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		clientCtx := transport.NewClientContext(
			principal.NewContext(context.Background(), gatewayPrincipal),
			backendServiceTr,
		)

		clientPropagateHandler := fx.authnMiddleware.Client()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "client propagated", nil
		})

		_, err = clientPropagateHandler(clientCtx, nil)
		require.NoError(t, err)

		// === Step 3: Server 授权失败 ===
		serverTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		propagatedPrincipal := backendServiceTr.RequestHeader().Get(principal.MetadataKey)
		serverTr.RequestHeader().Set(principal.MetadataKey, propagatedPrincipal)
		serverCtx := transport.NewServerContext(context.Background(), serverTr)

		serverAuthzHandler := kratosMiddleware.Chain(
			principalFromHeaderMiddleware(),
			fx.authzMiddleware.Server(),
		)(successHandler)

		_, err = serverAuthzHandler(serverCtx, nil)
		require.Error(t, err, "Server should deny due to insufficient permissions")
		assert.True(t, securityv1.IsPermissionDenied(err), "Should return PermissionDenied error")
	})

	t.Run("Complete flow with invalid token at gateway", func(t *testing.T) {
		// === Step 1: Gateway 认证失败 ===
		gatewayTr := newMockTransport(t, "POST", "/documents.Service/Edit")
		gatewayTr.RequestHeader().Set("Authorization", "Bearer invalid-token")
		gatewayCtx := transport.NewServerContext(context.Background(), gatewayTr)

		gatewayAuthnHandler := fx.authnMiddleware.Server()(successHandler)

		_, err := gatewayAuthnHandler(gatewayCtx, nil)
		require.Error(t, err, "Gateway should reject invalid token")
		assert.True(t, securityv1.IsTokenInvalid(err), "Should return TokenInvalid error")

		// 由于 Gateway 认证失败，后续的 Client 和 Server 步骤不会执行
		// 这验证了认证失败时整个链路被正确阻断
	})
}
