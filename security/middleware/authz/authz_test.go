// Package authz implements the functions, types, and interfaces for the module.
package authz

import (
	"context"
	"errors" // Import the errors package
	"net/http"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/origadmin/runtime/interfaces/options" // Import options package
	"github.com/origadmin/runtime/middleware"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
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
	req       *http.Request
	operation string
}

func newMockTransport(t *testing.T, method, op string) *mockTransport {
	req, err := http.NewRequest(method, op, nil)
	require.NoError(t, err)
	return &mockTransport{
		req:       req,
		operation: op,
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

// mockAuthorizer implements authz.Authorizer for testing purposes.
type mockRule struct {
	Resource string
	Action   string
}
type mockAuthorizer struct {
	allowRules  map[mockRule][]string
	errToReturn error // New field to simulate a generic error
}

func newMockAuthorizer(rules map[mockRule][]string) *mockAuthorizer {
	return &mockAuthorizer{allowRules: rules}
}

// newMockAuthorizerWithError creates a mock authorizer that always returns the given error.
func newMockAuthorizerWithError(err error) *mockAuthorizer {
	return &mockAuthorizer{errToReturn: err}
}

// Authorized checks if the principal is authorized for the given rule specification.
func (m *mockAuthorizer) Authorized(ctx context.Context, p security.Principal, spec authz.RuleSpec) (bool, error) {
	if m.errToReturn != nil {
		return false, m.errToReturn
	}
	rule := mockRule{Resource: spec.Resource, Action: spec.Action}
	requiredRoles, ok := m.allowRules[rule]
	if !ok {
		return false, securityv1.ErrorPermissionDenied("no rule defined for resource %s and action %s", rule.Resource, rule.Action)
	}

	principalRoles := p.GetRoles()
	for _, requiredRole := range requiredRoles {
		for _, pr := range principalRoles {
			if pr == requiredRole {
				return true, nil // Authorized
			}
		}
	}
	return false, securityv1.ErrorPermissionDenied("principal does not have required roles for operation")
}

func runMiddleware(t *testing.T, authorizer authz.Authorizer, ctx context.Context, handler middleware.KHandler, opts ...options.Option) (interface{}, error) {
	t.Helper()
	mw := New(authorizer, opts...)
	return mw.Server()(handler)(ctx, nil)
}

func TestAuthZMiddleware_Success(t *testing.T) {
	testCases := []struct {
		name        string
		principal   security.Principal
		method      string
		operation   string
		authorizer  authz.Authorizer
		expectError bool
	}{
		{
			name:      "Admin user accessing admin operation",
			principal: principal.New("adminUser", principal.WithRoles([]string{"admin"})),
			method:    "GET",
			operation: "/admin.Service/GetData",
			authorizer: newMockAuthorizer(map[mockRule][]string{
				{Resource: "/admin.Service/GetData", Action: "read"}: {"admin"},
			}),
			expectError: false,
		},
		{
			name:      "Regular user accessing public operation",
			principal: principal.New("regularUser", principal.WithRoles([]string{"user"})),
			method:    "GET",
			operation: "/public.Service/GetInfo",
			authorizer: newMockAuthorizer(map[mockRule][]string{
				{Resource: "/public.Service/GetInfo", Action: "read"}: {"user", "admin", "anonymous"},
			}),
			expectError: false,
		},
		{
			name:      "User with multiple roles accessing allowed operation",
			principal: principal.New("multiRoleUser", principal.WithRoles([]string{"user", "editor"})),
			method:    "POST",
			operation: "/editor.Service/EditDoc",
			authorizer: newMockAuthorizer(map[mockRule][]string{
				{Resource: "/editor.Service/EditDoc", Action: "create"}: {"editor"},
			}),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newMockTransport(t, tc.method, tc.operation)
			ctx := transport.NewServerContext(context.Background(), tr)
			ctx = principal.NewContext(ctx, tc.principal) // Inject principal into context

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				p, ok := principal.FromContext(ctx)
				require.True(t, ok, "Principal should be in context")
				assert.Equal(t, tc.principal.GetID(), p.GetID())
				return "handler called", nil
			}

			_, err := runMiddleware(t, tc.authorizer, ctx, handler)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthZMiddleware_Failure(t *testing.T) {
	testCases := []struct {
		name        string
		principal   security.Principal
		method      string
		operation   string
		authorizer  authz.Authorizer
		expectError bool
	}{
		{
			name:      "Regular user accessing admin operation",
			principal: principal.New("regularUser", principal.WithRoles([]string{"user"})),
			method:    "GET",
			operation: "/admin.Service/GetData",
			authorizer: newMockAuthorizer(map[mockRule][]string{
				{Resource: "/admin.Service/GetData", Action: "read"}: {"admin"},
			}),
			expectError: true,
		},
		{
			name:      "Anonymous user accessing protected operation",
			principal: principal.Anonymous(),
			method:    "GET",
			operation: "/protected.Service/GetSecret",
			authorizer: newMockAuthorizer(map[mockRule][]string{
				{Resource: "/protected.Service/GetSecret", Action: "read"}: {"admin", "user"},
			}),
			expectError: true,
		},
		{
			name:      "User with no matching role for operation",
			principal: principal.New("viewer", principal.WithRoles([]string{"viewer"})),
			method:    "POST",
			operation: "/editor.Service/EditDoc",
			authorizer: newMockAuthorizer(map[mockRule][]string{
				{Resource: "/editor.Service/EditDoc", Action: "create"}: {"editor"},
			}),
			expectError: true,
		},
		{
			name:      "No principal in context",
			principal: nil, // Simulate no principal set by authn middleware
			method:    "GET",
			operation: "/any.Service/AnyOp",
			authorizer: newMockAuthorizer(map[mockRule][]string{
				{Resource: "/any.Service/AnyOp", Action: "read"}: {"admin", "user"},
			}),
			expectError: true,
		},
		{
			name:        "Authorizer returns generic error",
			principal:   principal.New("user", principal.WithRoles([]string{"user"})),
			method:      "GET",
			operation:   "/some.Service/SomeOp",
			authorizer:  newMockAuthorizerWithError(errors.New("internal authorizer error")), // Use the new constructor
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newMockTransport(t, tc.method, tc.operation)
			ctx := transport.NewServerContext(context.Background(), tr)

			if tc.principal != nil {
				ctx = principal.NewContext(ctx, tc.principal)
			}

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return "handler called", nil
			}

			_, err := runMiddleware(t, tc.authorizer, ctx, handler)
			assert.Error(t, err)
			if tc.principal == nil {
				assert.True(t, securityv1.IsCredentialsInvalid(err))
			} else {
				// Check if the authorizer was configured to return a specific error
				mockAuth, ok := tc.authorizer.(*mockAuthorizer)
				if ok && mockAuth.errToReturn != nil {
					assert.EqualError(t, err, mockAuth.errToReturn.Error())
				} else {
					assert.True(t, securityv1.IsPermissionDenied(err))
				}
			}
		})
	}
}

func TestAuthZMiddleware_SkipChecker(t *testing.T) {
	alwaysSkip := func(ctx context.Context, req security.Request) bool { return true }
	neverSkip := func(ctx context.Context, req security.Request) bool { return false }

	mockAuthz := newMockAuthorizer(map[mockRule][]string{
		{Resource: "/protected.Service/GetData", Action: "read"}: {"admin"},
	})

	t.Run("SkipChecker allows skipping authorization", func(t *testing.T) {
		tr := newMockTransport(t, "GET", "/protected.Service/GetData")
		ctx := transport.NewServerContext(context.Background(), tr)
		mw := New(mockAuthz, WithSkipChecker(alwaysSkip))
		_, err := mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "handler called", nil
		})(ctx, nil)
		assert.NoError(t, err)
	})

	t.Run("SkipChecker does not skip authorization", func(t *testing.T) {
		tr := newMockTransport(t, "GET", "/protected.Service/GetData")
		ctx := transport.NewServerContext(context.Background(), tr)

		mw := New(mockAuthz, WithSkipChecker(neverSkip))
		_, err := mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "handler called", nil
		})(ctx, nil)
		assert.Error(t, err)
		assert.True(t, securityv1.IsCredentialsInvalid(err))
	})

	t.Run("PathSkipChecker skips specific path", func(t *testing.T) {
		skipPathsMap := map[string]bool{
			"/public.Service/GetInfo": true,
		}
		var skipPaths []string
		for path := range skipPathsMap {
			skipPaths = append(skipPaths, path)
		}
		checker := PathSkipChecker(skipPaths...)
		mw := New(mockAuthz, WithSkipChecker(checker))

		tr := newMockTransport(t, "GET", "/public.Service/GetInfo")
		ctx := transport.NewServerContext(context.Background(), tr)
		_, err := mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "handler called", nil
		})(ctx, nil)
		assert.NoError(t, err)

		tr = newMockTransport(t, "GET", "/protected.Service/GetData")
		ctx = transport.NewServerContext(context.Background(), tr)
		_, err = mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "handler called", nil
		})(ctx, nil)
		assert.Error(t, err)
		assert.True(t, securityv1.IsCredentialsInvalid(err))
	})

	t.Run("CompositeSkipChecker combines checkers", func(t *testing.T) {
		// Define a simple CompositeSkipChecker for testing purposes if not found in security package
		compositeSkipChecker := func(checkers ...security.SkipChecker) security.SkipChecker {
			return func(ctx context.Context, req security.Request) bool {
				for _, checker := range checkers {
					if checker(ctx, req) {
						return true
					}
				}
				return false
			}
		}

		checker1 := PathSkipChecker("/path1")
		checker2 := PathSkipChecker("/path2")
		composite := compositeSkipChecker(checker1, checker2)
		mw := New(mockAuthz, WithSkipChecker(composite))

		tr := newMockTransport(t, "GET", "/path1")
		ctx := transport.NewServerContext(context.Background(), tr)
		_, err := mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil })(ctx, nil)
		assert.NoError(t, err)

		tr = newMockTransport(t, "GET", "/path2")
		ctx = transport.NewServerContext(context.Background(), tr)
		_, err = mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil })(ctx, nil)
		assert.NoError(t, err)

		tr = newMockTransport(t, "GET", "/path3")
		ctx = transport.NewServerContext(context.Background(), tr)
		_, err = mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil })(ctx, nil)
		assert.Error(t, err)
		assert.True(t, securityv1.IsCredentialsInvalid(err))
	})
}
