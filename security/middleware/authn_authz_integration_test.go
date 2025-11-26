// Package middleware provides common middleware for security.
package middleware

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	jwtv1 "github.com/origadmin/contrib/api/gen/go/security/authn/jwt/v1"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	casbinv1 "github.com/origadmin/contrib/api/gen/go/security/authz/casbin/v1"
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	jwtAuthn "github.com/origadmin/contrib/security/authn/jwt"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin"
	authnMiddleware "github.com/origadmin/contrib/security/middleware/authn"
	authzMiddleware "github.com/origadmin/contrib/security/middleware/authz"
	"github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/middleware"
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
	header    mockHeaderCarrier
	req       *http.Request
	operation string
}

func newMockTransport(operation string) *mockTransport {
	req, _ := http.NewRequest("GET", "/test", nil)
	return &mockTransport{
		header:    make(mockHeaderCarrier),
		req:       req,
		operation: operation,
	}
}

func (m *mockTransport) Kind() transport.Kind            { return transport.KindHTTP }
func (m *mockTransport) Endpoint() string                { return "" }
func (m *mockTransport) Operation() string               { return m.operation }
func (m *mockTransport) RequestHeader() transport.Header { return m.header }
func (m *mockTransport) ReplyHeader() transport.Header   { return m.header }

// Implement kratoshttp.Transporter interface
func (m *mockTransport) Request() *http.Request {
	return m.req
}

func (m *mockTransport) PathTemplate() string {
	return m.operation
}

var _ transport.Transporter = (*mockTransport)(nil)
var _ kratoshttp.Transporter = (*kratoshttp.Transport)(nil)

// mockAuthorizer implements authz.Authorizer for testing purposes.
type mockAuthorizer struct {
	allowRules map[string][]string // action -> required roles
}

func newMockAuthorizer(rules map[string][]string) *mockAuthorizer {
	return &mockAuthorizer{allowRules: rules}
}

// Authorized checks if the principal is authorized for the given rule specification.
func (m *mockAuthorizer) Authorized(ctx context.Context, p security.Principal, spec authz.RuleSpec) (bool, error) {
	action := spec.Action
	requiredRoles, ok := m.allowRules[action]
	if !ok {
		// No specific rule for this action, deny by default
		return false, securityv1.ErrorPermissionDenied("no rule defined for operation %s", action)
	}

	principalRoles := p.GetRoles()
	// Check if principal has any of the required roles
	for _, requiredRole := range requiredRoles {
		for _, pr := range principalRoles {
			if pr == requiredRole {
				return true, nil // Authorized
			}
		}
	}
	return false, securityv1.ErrorPermissionDenied("principal does not have required roles for operation %s", action) // No matching role found
}

// mockAuthenticator implements authn.Authenticator for testing purposes.
type mockAuthenticator struct {
	authenticateFunc func(ctx context.Context, cred security.Credential) (security.Principal, error)
	supportsFunc     func(cred security.Credential) bool
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx, cred)
	}
	return nil, securityv1.ErrorCredentialsInvalid("mock authenticator not configured")
}

func (m *mockAuthenticator) Supports(cred security.Credential) bool {
	if m.supportsFunc != nil {
		return m.supportsFunc(cred)
	}
	return true // Default to supporting all credentials for simplicity
}

// runAuthNAuthZMiddleware chains authn and authz middlewares.
func runAuthNAuthZMiddleware(t *testing.T, authnMw *authnMiddleware.Middleware, authzMw *authzMiddleware.Middleware, ctx context.Context, handler middleware.KHandler) (context.Context, interface{}, error) {
	t.Helper()
	// Chain authn and authz middlewares
	// The inner handler (authzMw.Server()(handler)) returns a new context.
	// The outer handler (authnMw.Server()(...)) also returns a new context.
	// We need to capture the context returned by the outermost middleware.
	finalCtx := ctx // Initialize finalCtx with the initial context
	wrappedHandler := authnMw.Server()(authzMw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
		finalCtx = ctx // Capture the context after all middlewares have run
		return handler(ctx, req)
	}))

	reply, err := wrappedHandler(ctx, nil)
	return finalCtx, reply, err
}

// createJWTAuthenticator creates a JWT authenticator for testing
func createJWTAuthenticator(t *testing.T, secret string) authn.Authenticator {
	t.Helper()

	cfg := &authnv1.Authenticator{
		Type: "jwt",
		Jwt: &jwtv1.Config{
			SigningMethod:        "HS256",
			SigningKey:           secret,
			Issuer:               "test-issuer",
			AccessTokenLifetime:  3600,  // 1 hour in seconds
			RefreshTokenLifetime: 86400, // 24 hours in seconds
		},
	}

	authenticator, err := jwtAuthn.NewAuthenticator(cfg)
	require.NoError(t, err)
	return authenticator
}

// createCasbinAuthorizer creates a Casbin authorizer for testing
func createCasbinAuthorizer(t *testing.T, model string, policy string) authz.Authorizer {
	t.Helper()

	// Parse policy lines and create embedded policies
	policyLines := []string{}
	for _, line := range strings.Split(policy, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			policyLines = append(policyLines, line)
		}
	}

	var embeddedPolicies []*casbinv1.Policy
	for _, line := range policyLines {
		if strings.HasPrefix(line, "p,") {
			parts := strings.Split(line, ",")
			if len(parts) >= 4 {
				domain := "*"
				if len(parts) >= 5 {
					domain = strings.TrimSpace(parts[4])
				}
				embeddedPolicies = append(embeddedPolicies, &casbinv1.Policy{
					Subject: strings.TrimSpace(parts[1]),
					Object:  strings.TrimSpace(parts[2]),
					Action:  strings.TrimSpace(parts[3]),
					Domain:  []string{domain},
				})
			}
		}
	}

	cfg := &authzv1.Authorizer{
		Type: authz.Casbin,
		Casbin: &casbinv1.Config{
			ModelPath:        "", // Use default model
			PolicyPath:       "", // Use embedded policies
			EmbeddedPolicies: embeddedPolicies,
		},
	}

	authorizer, err := casbin.NewAuthorizer(cfg)
	require.NoError(t, err)
	return authorizer
}

// generateJWTToken generates a JWT token for testing
func generateJWTToken(t *testing.T, secret string, userID string, roles []string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"roles": roles,
		"iss":   "test-issuer",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return tokenString
}

// successHandler is a simple handler that returns success
func successHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return "success", nil
}

func TestAuthNAuthZIntegration(t *testing.T) {
	const testSecret = "test-secret-key"

	// Casbin model and policy for testing
	const casbinModel = `
[request_definition]
r = sub, obj, act, dom

[policy_definition]
p = sub, obj, act, dom

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act && r.dom == p.dom
`

	const casbinPolicy = `
p, alice, /admin.Service/GetData, read, *
p, bob, /public.Service/GetInfo, read, *
p, charlie, /documents.Service/Edit, write, *
p, bob, /documents.Service/View, read, *
`

	// Mode 1: Standalone Application Tests
	t.Run("Mode 1: Standalone Application", func(t *testing.T) {
		t.Run("Successful Authn & Authz", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			// Generate valid JWT token for admin user
			token := generateJWTToken(t, testSecret, "alice", []string{"admin"})

			tr := newMockTransport("/admin.Service/GetData")
			tr.RequestHeader().Set("Authorization", "Bearer "+token)
			initialCtx := transport.NewServerContext(context.Background(), tr)

			finalCtx, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.NoError(t, err, "Expected no error for successful authn and authz")

			p, ok := principal.FromContext(finalCtx)
			require.True(t, ok, "Principal should be in context")
			assert.Equal(t, "alice", p.GetID())
		})

		t.Run("Successful Authn, Failed Authz", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			// Generate valid JWT token for regular user
			token := generateJWTToken(t, testSecret, "bob", []string{"user"})

			tr := newMockTransport("/admin.Service/GetData")
			tr.RequestHeader().Set("Authorization", "Bearer "+token)
			initialCtx := transport.NewServerContext(context.Background(), tr)

			_, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.Error(t, err, "Expected authorization error")
			assert.True(t, securityv1.IsPermissionDenied(err), "Expected PermissionDenied error")
		})

		t.Run("Failed Authn", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			tr := newMockTransport("/admin.Service/GetData")
			tr.RequestHeader().Set("Authorization", "Bearer invalid-token")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			finalCtx, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.Error(t, err, "Expected authentication error")
			assert.True(t, securityv1.IsCredentialsInvalid(err), "Expected CredentialsInvalid error")

			_, ok := principal.FromContext(finalCtx)
			assert.False(t, ok, "Principal should NOT be in context after failed authn")
		})
	})

	// Mode 2: Microservices (API Gateway handles Authn/Authz)
	t.Run("Mode 2: API Gateway Pattern", func(t *testing.T) {
		t.Run("Gateway Authn/Authz Success", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			// Simulate API Gateway request
			token := generateJWTToken(t, testSecret, "gatewayUser", []string{"api-user"})

			tr := newMockTransport("/api/v1/resource")
			tr.RequestHeader().Set("Authorization", "Bearer "+token)
			tr.RequestHeader().Set("X-Gateway-Request", "true")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			finalCtx, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.NoError(t, err, "Gateway should successfully authenticate and authorize")

			p, ok := principal.FromContext(finalCtx)
			require.True(t, ok, "Principal should be set by gateway")
			assert.Equal(t, "gatewayUser", p.GetID())
		})

		t.Run("Gateway Authn/Authz Failure", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			// User with insufficient permissions
			token := generateJWTToken(t, testSecret, "gatewayUser", []string{"api-user"})

			tr := newMockTransport("/api/v1/admin-resource")
			tr.RequestHeader().Set("Authorization", "Bearer "+token)
			tr.RequestHeader().Set("X-Gateway-Request", "true")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			_, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.Error(t, err, "Gateway should deny access")
			assert.True(t, securityv1.IsPermissionDenied(err), "Expected PermissionDenied error")
		})
	})

	// Mode 3: Microservices (Dedicated Auth Service)
	t.Run("Mode 3: Dedicated Auth Service", func(t *testing.T) {
		t.Run("Gateway -> Auth Service Success", func(t *testing.T) {
			// Simulate auth service response by using JWT authn
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			token := generateJWTToken(t, testSecret, "authServiceUser", []string{"service-user"})

			tr := newMockTransport("/serviceA/data")
			tr.RequestHeader().Set("Authorization", "Bearer "+token)
			tr.RequestHeader().Set("X-Auth-Service", "validated")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			finalCtx, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.NoError(t, err, "Auth service should validate and authorize")

			p, ok := principal.FromContext(finalCtx)
			require.True(t, ok, "Principal should be set after auth service validation")
			assert.Equal(t, "authServiceUser", p.GetID())
		})

		t.Run("Gateway -> Auth Service Authn Failure", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			tr := newMockTransport("/serviceA/data")
			tr.RequestHeader().Set("Authorization", "Bearer invalid-token")
			tr.RequestHeader().Set("X-Auth-Service", "validated")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			_, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.Error(t, err, "Auth service should reject invalid token")
			assert.True(t, securityv1.IsCredentialsInvalid(err), "Expected CredentialsInvalid error")
		})
	})

	// Mode 4: Authn Only
	t.Run("Mode 4: Authn Only Policy", func(t *testing.T) {
		t.Run("Successful Authn (Authn Only)", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			// No authz middleware for authn-only policy
			authnMw := authnMiddleware.NewAuthNMiddleware(authn)

			token := generateJWTToken(t, testSecret, "user123", []string{"user"})

			tr := newMockTransport("/public/resource")
			tr.RequestHeader().Set("Authorization", "Bearer "+token)
			tr.RequestHeader().Set("X-Policy", "authn-only")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			// Only run authn middleware
			wrappedHandler := authnMw.Server()(successHandler)
			_, err := wrappedHandler(initialCtx, nil)
			assert.NoError(t, err, "Authn-only should succeed with valid credentials")
		})

		t.Run("Failed Authn (Authn Only)", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authnMw := authnMiddleware.NewAuthNMiddleware(authn)

			tr := newMockTransport("/public/resource")
			tr.RequestHeader().Set("Authorization", "Bearer invalid-token")
			tr.RequestHeader().Set("X-Policy", "authn-only")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			wrappedHandler := authnMw.Server()(successHandler)
			_, err := wrappedHandler(initialCtx, nil)
			assert.Error(t, err, "Authn-only should fail with invalid credentials")
			assert.True(t, securityv1.IsCredentialsInvalid(err), "Expected CredentialsInvalid error")
		})
	})

	// Mode 5: Authz Only
	t.Run("Mode 5: Authz Only Policy", func(t *testing.T) {
		t.Run("Anonymous Authz Success", func(t *testing.T) {
			// No authn middleware, only authz
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			tr := newMockTransport("/public/info")
			// No Authorization header - simulate anonymous
			initialCtx := transport.NewServerContext(context.Background(), tr)

			// Manually set anonymous principal in context
			anonymousCtx := principal.NewContext(initialCtx, principal.Anonymous())

			wrappedHandler := authzMw.Server()(successHandler)
			_, err := wrappedHandler(anonymousCtx, nil)
			assert.NoError(t, err, "Anonymous should access public resource")
		})

		t.Run("Anonymous Authz Failure", func(t *testing.T) {
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			tr := newMockTransport("/protected/data")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			// Manually set anonymous principal in context
			anonymousCtx := principal.NewContext(initialCtx, principal.Anonymous())

			wrappedHandler := authzMw.Server()(successHandler)
			_, err := wrappedHandler(anonymousCtx, nil)
			assert.Error(t, err, "Anonymous should be denied access to protected resource")
			assert.True(t, securityv1.IsPermissionDenied(err), "Expected PermissionDenied error")
		})

		t.Run("No Principal, Authz Only", func(t *testing.T) {
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			tr := newMockTransport("/protected/data")
			initialCtx := transport.NewServerContext(context.Background(), tr)
			// No principal set in context

			wrappedHandler := authzMw.Server()(successHandler)
			_, err := wrappedHandler(initialCtx, nil)
			assert.Error(t, err, "Should fail when no principal in context")
			assert.True(t, securityv1.IsCredentialsInvalid(err), "Expected CredentialsInvalid error")
		})
	})

	// Mode 6: Authn + Authz (Full Policy)
	t.Run("Mode 6: Full Authn/Authz Policy", func(t *testing.T) {
		t.Run("Full Authn/Authz Success", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			token := generateJWTToken(t, testSecret, "fullUser", []string{"editor"})

			tr := newMockTransport("/documents.Service/Edit")
			tr.RequestHeader().Set("Authorization", "Bearer "+token)
			tr.RequestHeader().Set("X-Policy", "full")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			finalCtx, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.NoError(t, err, "Full policy should succeed with proper authn and authz")

			p, ok := principal.FromContext(finalCtx)
			require.True(t, ok, "Principal should be in context")
			assert.Equal(t, "fullUser", p.GetID())
		})

		t.Run("Full Authn Success, Authz Failure", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			// User with viewer role trying to edit
			token := generateJWTToken(t, testSecret, "fullUser", []string{"viewer"})

			tr := newMockTransport("/documents.Service/Edit")
			tr.RequestHeader().Set("Authorization", "Bearer "+token)
			tr.RequestHeader().Set("X-Policy", "full")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			_, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.Error(t, err, "Should fail authorization despite successful authentication")
			assert.True(t, securityv1.IsPermissionDenied(err), "Expected PermissionDenied error")
		})

		t.Run("Full Authn Failure", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz)

			tr := newMockTransport("/documents.Service/Edit")
			tr.RequestHeader().Set("Authorization", "Bearer invalid-token")
			tr.RequestHeader().Set("X-Policy", "full")
			initialCtx := transport.NewServerContext(context.Background(), tr)

			finalCtx, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.Error(t, err, "Should fail authentication")
			assert.True(t, securityv1.IsCredentialsInvalid(err), "Expected CredentialsInvalid error")

			_, ok := principal.FromContext(finalCtx)
			assert.False(t, ok, "Principal should NOT be in context after failed authn")
		})
	})

	// SkipChecker Tests
	t.Run("SkipChecker Tests", func(t *testing.T) {
		t.Run("PathSkipChecker skips specific path", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			// Create skip checker for health endpoint
			skipPaths := map[string]bool{"/health": true}
			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz,
				authzMiddleware.WithSkipChecker(authzMiddleware.PathSkipChecker(skipPaths)))

			tr := newMockTransport("/health")
			// No authorization header
			initialCtx := transport.NewServerContext(context.Background(), tr)

			_, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.NoError(t, err, "Should skip authz for health endpoint")
		})

		t.Run("SkipChecker does not skip authorization", func(t *testing.T) {
			authn := createJWTAuthenticator(t, testSecret)
			authz := createCasbinAuthorizer(t, casbinModel, casbinPolicy)

			// Skip checker that never skips
			var skipChecker authzMiddleware.SkipChecker = func(req security.Request) bool { return false }
			authnMw := authnMiddleware.NewAuthNMiddleware(authn)
			authzMw := authzMiddleware.NewAuthZMiddleware(authz,
				authzMiddleware.WithSkipChecker(skipChecker))

			tr := newMockTransport("/protected/data")
			// No authorization header
			initialCtx := transport.NewServerContext(context.Background(), tr)

			_, _, err := runAuthNAuthZMiddleware(t, authnMw, authzMw, initialCtx, successHandler)
			assert.Error(t, err, "Should not skip authorization when skipChecker returns false")
			assert.True(t, securityv1.IsCredentialsInvalid(err), "Expected CredentialsInvalid error")
		})
	})
}
