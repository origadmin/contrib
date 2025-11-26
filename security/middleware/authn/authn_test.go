package authn

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/authn/jwt"
	"github.com/origadmin/contrib/security/authn/noop"
	securityCredential "github.com/origadmin/contrib/security/credential"
	"github.com/origadmin/contrib/security/principal"
)

// mockHeaderCarrier implements transport.Header
type mockHeaderCarrier map[string][]string

func (m mockHeaderCarrier) Get(key string) string {
	if v := m[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (m mockHeaderCarrier) Set(key string, value string) {
	m[key] = []string{value}
}

func (m mockHeaderCarrier) Add(key string, value string) {
	m[key] = append(m[key], value)
}

func (m mockHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (m mockHeaderCarrier) Values(key string) []string {
	return m[key]
}

// mockTransport is a mock implementation of transport.Transport and kratoshttp.Transporter
type mockTransport struct {
	header mockHeaderCarrier
	req    *http.Request
}

func newMockTransport() *mockTransport {
	req, _ := http.NewRequest("GET", "/test", nil)
	return &mockTransport{
		header: make(mockHeaderCarrier),
		req:    req,
	}
}

func (m *mockTransport) Kind() transport.Kind            { return transport.KindHTTP }
func (m *mockTransport) Endpoint() string                { return "" }
func (m *mockTransport) Operation() string               { return "/test.Service/Test" }
func (m *mockTransport) RequestHeader() transport.Header { return m.header }
func (m *mockTransport) ReplyHeader() transport.Header   { return m.header }

// Implement kratoshttp.Transporter interface
func (m *mockTransport) Request() *http.Request {
	return m.req
}

func (m *mockTransport) PathTemplate() string {
	return "/test.Service/Test"
}

type header interface {
	Get(key string) string
	Set(key string, value string)
	Add(key string, value string)
	Keys() []string
	Values(key string) []string
}

var _ transport.Transporter = (*mockTransport)(nil)
var _ kratoshttp.Transporter = (*mockTransport)(nil)

func runMiddleware(t *testing.T, authn authn.Authenticator, ctx context.Context) (context.Context, error) {
	t.Helper()
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "handler called", nil
	}
	mw := NewAuthNMiddleware(authn)
	_, err := mw.Server()(handler)(ctx, nil)
	return ctx, err
}

func TestAuthNMiddleware_WithNoopAuthenticator(t *testing.T) {
	// 1. Setup authenticator
	noopAuthn, err := noop.NewAuthenticator(nil)
	require.NoError(t, err)

	// 2. Setup context with transport
	tr := newMockTransport()
	ctx := transport.NewServerContext(context.Background(), tr)

	// 3. Run middleware
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		p, ok := principal.FromContext(ctx)
		require.True(t, ok, "Principal should be in context")
		assert.Equal(t, principal.Anonymous().GetID(), p.GetID(), "Principal should be anonymous")
		return "handler called", nil
	}
	mw := NewAuthNMiddleware(noopAuthn)
	_, err = mw.Server()(handler)(ctx, nil)
	require.NoError(t, err)
}

func TestAuthNMiddleware_WithJwtAuthenticator_Success(t *testing.T) {
	// 1. Setup JWT Authenticator
	secret := []byte("test-secret-key")
	issuer := "test-issuer"
	jwtCfg := &authnv1.Authenticator{
		Jwt: &jwtv1.Config{Issuer: issuer},
	}
	jwtAuthn, err := jwt.NewAuthenticator(
		jwtCfg,
		jwt.WithSigningMethod(jwtv5.SigningMethodHS256),
		jwt.WithKeyFunc(func(token *jwtv5.Token) (interface{}, error) {
			return secret, nil
		}),
	)
	require.NoError(t, err)

	// 2. Create a valid token
	creator, ok := jwtAuthn.(securityCredential.Creator)
	require.True(t, ok)
	testPrincipal := principal.New("user123", []string{"users"}, nil, nil, nil)
	resp, err := creator.CreateCredential(context.Background(), testPrincipal)
	require.NoError(t, err)
	tokenString := resp.Payload().GetToken().GetAccessToken()

	// 3. Setup context with transport and token
	tr := newMockTransport()
	tr.RequestHeader().Set("Authorization", "Bearer "+tokenString)
	ctx := transport.NewServerContext(context.Background(), tr)

	// 4. Run middleware and verify principal
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		p, ok := principal.FromContext(ctx)
		require.True(t, ok, "Principal should be in context")
		assert.Equal(t, "user123", p.GetID())
		assert.Equal(t, []string{"users"}, p.GetRoles())
		return "handler called", nil
	}
	mw := NewAuthNMiddleware(jwtAuthn)
	_, err = mw.Server()(handler)(ctx, nil)
	require.NoError(t, err)
}

func TestAuthNMiddleware_WithJwtAuthenticator_Failure(t *testing.T) {
	// 1. Setup JWT Authenticator
	secret := []byte("test-secret-key")
	issuer := "test-issuer"
	jwtCfg := &authnv1.Authenticator{
		Type: "jwt",
		Jwt:  &jwtv1.Config{Issuer: issuer},
	}
	jwtAuthn, err := jwt.NewAuthenticator(
		jwtCfg,
		jwt.WithSigningMethod(jwtv5.SigningMethodHS256),
		jwt.WithKeyFunc(func(token *jwtv5.Token) (interface{}, error) {
			return secret, nil
		}),
	)
	require.NoError(t, err)

	// 2. Create an expired token
	expiredClaims := &jwt.Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "expired-user",
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		},
	}
	expiredToken, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, expiredClaims).SignedString(secret)
	require.NoError(t, err)

	testCases := []struct {
		name        string
		tokenHeader string
		expectError bool
	}{
		{"No Token", "", true}, // No token should result in error from JWT authenticator
		{"Malformed Token", "Bearer malformed", true},
		{"Invalid Signature", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},
		{"Expired Token", "Bearer " + expiredToken, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newMockTransport()
			if tc.tokenHeader != "" {
				tr.RequestHeader().Set("Authorization", tc.tokenHeader)
			}
			ctx := transport.NewServerContext(context.Background(), tr)

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				// This handler should only be called if there's no error
				return "handler called", nil
			}

			mw := NewAuthNMiddleware(jwtAuthn)
			_, err := mw.Server()(handler)(ctx, nil)

			if tc.expectError {
				assert.Error(t, err, "Expected an error for case: %s", tc.name)
			} else {
				// For cases that should not error
				assert.NoError(t, err, "Expected no error for case: %s", tc.name)
				p, ok := principal.FromContext(ctx)
				require.True(t, ok)
				assert.Equal(t, principal.Anonymous().GetID(), p.GetID())
			}
		})
	}
}

// ===== Architecture Deployment Mode Tests =====
// The following tests are based on the three deployment modes described in the architecture document

// TestDeploymentMode_Standalone tests Mode 1: Monolithic Application
func TestDeploymentMode_Standalone(t *testing.T) {
	t.Run("JWT authenticator in monolithic application", func(t *testing.T) {
		// 1. Setup JWT authenticator
		secret := []byte("standalone-secret")
		issuer := "standalone-app"
		jwtCfg := &authnv1.Authenticator{
			Jwt: &jwtv1.Config{Issuer: issuer},
		}
		jwtAuthn, err := jwt.NewAuthenticator(
			jwtCfg,
			jwt.WithSigningMethod(jwtv5.SigningMethodHS256),
			jwt.WithKeyFunc(func(token *jwtv5.Token) (interface{}, error) {
				return secret, nil
			}),
		)
		require.NoError(t, err)

		// 2. Create a valid token and set it in the request
		creator, ok := jwtAuthn.(securityCredential.Creator)
		require.True(t, ok)
		testPrincipal := principal.New("user123", []string{"users", "admin"}, []string{"read", "write"}, nil, nil)
		resp, err := creator.CreateCredential(context.Background(), testPrincipal)
		require.NoError(t, err)
		tokenCred := resp.Payload().GetToken()

		// 3. Simulate request handling in a monolithic application
		tr := newMockTransport()
		tr.RequestHeader().Set("Authorization", "Bearer "+tokenCred.GetAccessToken())
		ctx := transport.NewServerContext(context.Background(), tr)

		// 4. Execute middleware and verify Principal
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Principal should be in context")
			assert.Equal(t, "user123", p.GetID())
			assert.Equal(t, []string{"users", "admin"}, p.GetRoles())
			assert.Equal(t, []string{"read", "write"}, p.GetPermissions())
			return "handler called", nil
		}
		mw := NewAuthNMiddleware(jwtAuthn)
		_, err = mw.Server()(handler)(ctx, nil)
		require.NoError(t, err)
	})

	t.Run("Noop authenticator in monolithic application", func(t *testing.T) {
		// 1. Setup Noop authenticator
		noopAuthn, err := noop.NewAuthenticator(nil)
		require.NoError(t, err)

		// 2. Simulate request handling in a monolithic application (no authentication)
		tr := newMockTransport()
		ctx := transport.NewServerContext(context.Background(), tr)

		// 3. Execute middleware and verify anonymous Principal
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Principal should be in context")
			assert.Equal(t, principal.Anonymous().GetID(), p.GetID())
			return "handler called", nil
		}
		mw := NewAuthNMiddleware(noopAuthn)
		_, err = mw.Server()(handler)(ctx, nil)
		require.NoError(t, err)
	})
}

// TestDeploymentMode_Microservice_Gateway tests Mode 2: Microservices (without independent auth service)
func TestDeploymentMode_Microservice_Gateway(t *testing.T) {
	t.Run("JWT authentication in API Gateway", func(t *testing.T) {
		// 1. Setup JWT authenticator in API Gateway
		secret := []byte("gateway-secret")
		issuer := "api-gateway"
		jwtCfg := &authnv1.Authenticator{
			Jwt: &jwtv1.Config{Issuer: issuer},
		}
		gatewayAuthn, err := jwt.NewAuthenticator(
			jwtCfg,
			jwt.WithSigningMethod(jwtv5.SigningMethodHS256),
			jwt.WithKeyFunc(func(token *jwtv5.Token) (interface{}, error) {
				return secret, nil
			}),
		)
		require.NoError(t, err)

		// 2. Simulate client request reaching API Gateway
		creator, ok := gatewayAuthn.(securityCredential.Creator)
		require.True(t, ok)
		userPrincipal := principal.New("user456", []string{"api-user"}, []string{"api:read"}, nil, nil)
		resp, err := creator.CreateCredential(context.Background(), userPrincipal)
		require.NoError(t, err)
		tokenCred := resp.Payload().GetToken()

		// 3. API Gateway validates token and prepares to forward to downstream services
		tr := newMockTransport()
		tr.RequestHeader().Set("Authorization", "Bearer "+tokenCred.GetAccessToken())
		ctx := transport.NewServerContext(context.Background(), tr)

		// 4. Gateway middleware performs authentication
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Gateway should authenticate and set Principal")
			assert.Equal(t, "user456", p.GetID())
			// 5. Simulate serializing Principal information to Headers for downstream services
			if tr, ok := transport.FromServerContext(ctx); ok {
				// In actual implementation, Principal information would be encoded and passed downstream here
				tr.ReplyHeader().Set("X-Principal-ID", p.GetID())
				tr.ReplyHeader().Set("X-Principal-Roles", "api-user")
			}

			return "forward to downstream service", nil
		}
		mw := NewAuthNMiddleware(gatewayAuthn)
		_, err = mw.Server()(handler)(ctx, nil)
		require.NoError(t, err)

		// 6. Verify Headers passed to downstream services
		assert.Equal(t, "user456", tr.ReplyHeader().Get("X-Principal-ID"))
		assert.Equal(t, "api-user", tr.ReplyHeader().Get("X-Principal-Roles"))
	})

	t.Run("Gateway authentication failure scenario", func(t *testing.T) {
		secret := []byte("gateway-secret")
		issuer := "api-gateway"
		jwtCfg := &authnv1.Authenticator{
			Jwt: &jwtv1.Config{Issuer: issuer},
		}
		gatewayAuthn, err := jwt.NewAuthenticator(
			jwtCfg,
			jwt.WithSigningMethod(jwtv5.SigningMethodHS256),
			jwt.WithKeyFunc(func(token *jwtv5.Token) (interface{}, error) {
				return secret, nil
			}),
		)
		require.NoError(t, err)

		// Test with invalid token
		tr := newMockTransport()
		tr.RequestHeader().Set("Authorization", "Bearer invalid-token")
		ctx := transport.NewServerContext(context.Background(), tr)

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return "should not reach here", nil
		}
		mw := NewAuthNMiddleware(gatewayAuthn)
		_, err = mw.Server()(handler)(ctx, nil)
		assert.Error(t, err, "Gateway should reject invalid token")
	})
}

// TestDeploymentMode_Microservice_IndependentAuth tests Mode 3: Microservices (with independent auth service)
func TestDeploymentMode_Microservice_IndependentAuth(t *testing.T) {
	t.Run("Independent authentication service mode", func(t *testing.T) {
		// 1. Setup JWT authenticator for independent authentication service
		secret := []byte("auth-service-secret")
		issuer := "auth-service"
		authServiceCfg := &authnv1.Authenticator{
			Jwt: &jwtv1.Config{Issuer: issuer},
		}
		authServiceAuthn, err := jwt.NewAuthenticator(
			authServiceCfg,
			jwt.WithSigningMethod(jwtv5.SigningMethodHS256),
			jwt.WithKeyFunc(func(token *jwtv5.Token) (interface{}, error) {
				return secret, nil
			}),
		)
		require.NoError(t, err)

		// 2. Simulate user login to obtain token
		creator, ok := authServiceAuthn.(securityCredential.Creator)
		require.True(t, ok)
		userPrincipal := principal.New("user789", []string{"service-user"}, []string{"service:access"}, nil, nil)
		resp, err := creator.CreateCredential(context.Background(), userPrincipal)
		require.NoError(t, err)
		tokenCred := resp.Payload().GetToken()

		// 3. Simulate API gateway as lightweight proxy calling auth service to validate token
		validateTokenWithAuthService := func(token string) (security.Principal, error) {
			// In actual implementation, this would call the auth service via RPC/HTTP
			// Here we directly call the auth service method to simulate
			payload := &securityv1.BearerCredential{Token: token}
			cred, err := securityCredential.NewCredential("jwt", token, payload, nil)
			if err != nil {
				return nil, err
			}
			return authServiceAuthn.Authenticate(context.Background(), cred)
		}

		// 4. Gateway validates token
		validatedPrincipal, err := validateTokenWithAuthService(tokenCred.GetAccessToken())
		require.NoError(t, err)
		assert.Equal(t, "user789", validatedPrincipal.GetID())

		// 5. Gateway passes validation result to downstream business services
		tr := newMockTransport()
		tr.RequestHeader().Set("Authorization", "Bearer "+tokenCred.GetAccessToken())
		ctx := transport.NewServerContext(context.Background(), tr)

		// 6. Simulate gateway middleware (lightweight proxy)
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			// In actual implementation, this would call the auth service instead of validating directly
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Principal should be in context")
			assert.Equal(t, "user789", p.GetID())

			// Set headers to pass to downstream services
			if tr, ok := transport.FromServerContext(ctx); ok {
				tr.ReplyHeader().Set("X-User-ID", p.GetID())
				tr.ReplyHeader().Set("X-User-Roles", "service-user")
			}

			return "business logic executed", nil
		}

		// Use a mock gateway authenticator (in reality would call auth service)
		gatewayAuthn := &mockGatewayAuthenticator{
			authService: authServiceAuthn,
		}
		mw := NewAuthNMiddleware(gatewayAuthn)
		_, err = mw.Server()(handler)(ctx, nil)
		require.NoError(t, err)

		// 7. Verify information passed to downstream business services
		assert.Equal(t, "user789", tr.ReplyHeader().Get("X-User-ID"))
		assert.Equal(t, "service-user", tr.ReplyHeader().Get("X-User-Roles"))
	})
}

// mockGatewayAuthenticator simulates a lightweight authenticator in the gateway
type mockGatewayAuthenticator struct {
	authService authn.Authenticator
}

func (m *mockGatewayAuthenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	// In actual implementation, this would call the auth service via RPC/HTTP
	return m.authService.Authenticate(ctx, cred)
}

func (m *mockGatewayAuthenticator) Supports(cred security.Credential) bool {
	return m.authService.Supports(cred)
}

// TestAuthnAuthz_CombinationModes tests authentication and authorization combination modes
func TestAuthnAuthz_CombinationModes(t *testing.T) {
	t.Run("Authentication-only mode", func(t *testing.T) {
		// 1. Setup JWT authenticator
		secret := []byte("authn-only-secret")
		issuer := "authn-only-service"
		jwtCfg := &authnv1.Authenticator{
			Jwt: &jwtv1.Config{Issuer: issuer},
		}
		authnOnly, err := jwt.NewAuthenticator(
			jwtCfg,
			jwt.WithSigningMethod(jwtv5.SigningMethodHS256),
			jwt.WithKeyFunc(func(token *jwtv5.Token) (interface{}, error) {
				return secret, nil
			}),
		)
		require.NoError(t, err)

		// 2. Create token
		creator, ok := authnOnly.(securityCredential.Creator)
		require.True(t, ok)
		testPrincipal := principal.New("readonly-user", []string{"readonly"}, []string{}, nil, nil)
		resp, err := creator.CreateCredential(context.Background(), testPrincipal)
		require.NoError(t, err)
		tokenCred := resp.Payload().GetToken()

		// 3. Test authentication-only scenario
		tr := newMockTransport()
		tr.RequestHeader().Set("Authorization", "Bearer "+tokenCred.GetAccessToken())
		ctx := transport.NewServerContext(context.Background(), tr)

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Authentication-only mode should set Principal")
			assert.Equal(t, "readonly-user", p.GetID())
			// Business logic can personalize based on Principal but doesn't check permissions
			return "personalized data for " + p.GetID(), nil
		}
		mw := NewAuthNMiddleware(authnOnly)
		result, err := mw.Server()(handler)(ctx, nil)
		require.NoError(t, err)
		assert.Equal(t, "personalized data for readonly-user", result)
	})

	t.Run("Anonymous access mode", func(t *testing.T) {
		// 1. Use Noop authenticator to allow anonymous access
		noopAuthn, err := noop.NewAuthenticator(nil)
		require.NoError(t, err)

		// 2. Test anonymous access without token
		tr := newMockTransport()
		ctx := transport.NewServerContext(context.Background(), tr)

		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok, "Should have anonymous Principal")
			assert.Equal(t, principal.Anonymous().GetID(), p.GetID())
			return "public data", nil
		}
		mw := NewAuthNMiddleware(noopAuthn)
		result, err := mw.Server()(handler)(ctx, nil)
		require.NoError(t, err)
		assert.Equal(t, "public data", result)
	})
}

// TestCrossService_PrincipalPropagation tests Principal propagation across services
func TestCrossService_PrincipalPropagation(t *testing.T) {
	t.Run("Principal propagation between microservices", func(t *testing.T) {
		// 1. Setup authentication service
		secret := []byte("cross-service-secret")
		issuer := "auth-service"
		authServiceCfg := &authnv1.Authenticator{
			Jwt: &jwtv1.Config{Issuer: issuer},
		}
		authServiceAuthn, err := jwt.NewAuthenticator(
			authServiceCfg,
			jwt.WithSigningMethod(jwtv5.SigningMethodHS256),
			jwt.WithKeyFunc(func(token *jwtv5.Token) (interface{}, error) {
				return secret, nil
			}),
		)
		require.NoError(t, err)

		// 2. Create user token
		creator, ok := authServiceAuthn.(securityCredential.Creator)
		require.True(t, ok)
		userPrincipal := principal.New("cross-service-user", []string{"user", "api-access"}, []string{"cross:call"}, nil, nil)
		resp, err := creator.CreateCredential(context.Background(), userPrincipal)
		require.NoError(t, err)
		tokenCred := resp.Payload().GetToken()

		// 3. Simulate Service A receiving request and calling Service B
		serviceATransport := newMockTransport()
		serviceATransport.RequestHeader().Set("Authorization", "Bearer "+tokenCred.GetAccessToken())
		serviceACtx := transport.NewServerContext(context.Background(), serviceATransport)

		// Service A middleware
		serviceAHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			p, ok := principal.FromContext(ctx)
			require.True(t, ok)
			assert.Equal(t, "cross-service-user", p.GetID())

			// Prepare to call Service B, pass Principal information
			if tr, ok := transport.FromServerContext(ctx); ok {
				// In actual implementation, Principal information would be encoded and passed via gRPC metadata or HTTP headers
				tr.ReplyHeader().Set("X-Forward-User-ID", p.GetID())
				tr.ReplyHeader().Set("X-Forward-User-Roles", "user,api-access")
			}
			return "service A processed", nil
		}

		mwA := NewAuthNMiddleware(authServiceAuthn)
		_, err = mwA.Server()(serviceAHandler)(serviceACtx, nil)
		require.NoError(t, err)

		// 4. Simulate Service B receiving call from Service A
		serviceBTransport := newMockTransport()
		// Service B receives Principal information passed from Service A
		serviceBTransport.RequestHeader().Set("X-Forward-User-ID", "cross-service-user")
		serviceBTransport.RequestHeader().Set("X-Forward-User-Roles", "user,api-access")
		serviceBCtx := transport.NewServerContext(context.Background(), serviceBTransport)

		// Service B needs to be able to reconstruct Principal from Headers
		serviceBHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
			// In actual implementation, Service B would have middleware to reconstruct Principal from Headers
			if tr, ok := transport.FromServerContext(ctx); ok {
				userID := tr.RequestHeader().Get("X-Forward-User-ID")
				userRoles := tr.RequestHeader().Get("X-Forward-User-Roles")

				// Reconstruct Principal and inject into context
				reconstructedPrincipal := principal.New(userID, []string{userRoles}, []string{}, nil, nil)
				ctx = principal.NewContext(ctx, reconstructedPrincipal)

				p, ok := principal.FromContext(ctx)
				require.True(t, ok)
				assert.Equal(t, "cross-service-user", p.GetID())

				return "service B processed for user: " + p.GetID(), nil
			}
			return "no principal info", nil
		}

		// Service B uses Noop authenticator since authentication was completed in Service A
		noopAuthn, _ := noop.NewAuthenticator(nil)
		mwB := NewAuthNMiddleware(noopAuthn)
		result, err := mwB.Server()(serviceBHandler)(serviceBCtx, nil)
		require.NoError(t, err)
		assert.Equal(t, "service B processed for user: cross-service-user", result)
	})
}
