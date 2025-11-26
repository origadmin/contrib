// Package authz implements the functions, types, and interfaces for the module.
package authz

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1" // Import securityv1
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
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
var _ kratoshttp.Transporter = (*kratoshttp.Transport)(nil) // Changed to kratoshttp.Transport for correctness

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

func runMiddleware(t *testing.T, authorizer authz.Authorizer, ctx context.Context, handler middleware.KHandler) (interface{}, error) {
	t.Helper()
	mw := NewAuthZMiddleware(authorizer)
	return mw.Server()(handler)(ctx, nil)
}

func TestAuthZMiddleware_Success(t *testing.T) {
	testCases := []struct {
		name        string
		principal   security.Principal
		operation   string
		authorizer  authz.Authorizer
		expectError bool
	}{
		{
			name:      "Admin user accessing admin operation",
			principal: principal.New("adminUser", []string{"admin"}, nil, nil, nil),
			operation: "/admin.Service/GetData",
			authorizer: newMockAuthorizer(map[string][]string{
				"/admin.Service/GetData": {"admin"},
			}),
			expectError: false,
		},
		{
			name:      "Regular user accessing public operation",
			principal: principal.New("regularUser", []string{"user"}, nil, nil, nil),
			operation: "/public.Service/GetInfo",
			authorizer: newMockAuthorizer(map[string][]string{
				"/public.Service/GetInfo": {"user", "admin", "anonymous"}, // Allow user, admin, or anonymous
			}),
			expectError: false,
		},
		{
			name:      "User with multiple roles accessing allowed operation",
			principal: principal.New("multiRoleUser", []string{"user", "editor"}, nil, nil, nil),
			operation: "/editor.Service/EditDoc",
			authorizer: newMockAuthorizer(map[string][]string{
				"/editor.Service/EditDoc": {"editor"},
			}),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newMockTransport(tc.operation)
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
		operation   string
		authorizer  authz.Authorizer
		expectError bool
	}{
		{
			name:      "Regular user accessing admin operation",
			principal: principal.New("regularUser", []string{"user"}, nil, nil, nil),
			operation: "/admin.Service/GetData",
			authorizer: newMockAuthorizer(map[string][]string{
				"/admin.Service/GetData": {"admin"},
			}),
			expectError: true, // Should be forbidden
		},
		{
			name:      "Anonymous user accessing protected operation",
			principal: principal.Anonymous(),
			operation: "/protected.Service/GetSecret",
			authorizer: newMockAuthorizer(map[string][]string{
				"/protected.Service/GetSecret": {"admin", "user"},
			}),
			expectError: true, // Should be forbidden
		},
		{
			name:      "User with no matching role for operation",
			principal: principal.New("viewer", []string{"viewer"}, nil, nil, nil),
			operation: "/editor.Service/EditDoc",
			authorizer: newMockAuthorizer(map[string][]string{
				"/editor.Service/EditDoc": {"editor"},
			}),
			expectError: true, // Should be forbidden
		},
		{
			name:      "No principal in context",
			principal: nil, // Simulate no principal set by authn middleware
			operation: "/any.Service/AnyOp",
			authorizer: newMockAuthorizer(map[string][]string{
				"/any.Service/AnyOp": {"admin", "user"},
			}),
			expectError: true, // Should return ErrUnauthorized
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newMockTransport(tc.operation)
			ctx := transport.NewServerContext(context.Background(), tr)
			if tc.principal != nil {
				ctx = principal.NewContext(ctx, tc.principal) // Inject principal if not nil
			}

			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return "handler called", nil // Should not be reached if authorization fails
			}

			_, err := runMiddleware(t, tc.authorizer, ctx, handler)
			assert.Error(t, err)
			if tc.principal == nil {
				assert.True(t, securityv1.IsCredentialsInvalid(err)) // Specific error for missing principal
			} else {
				assert.True(t, securityv1.IsPermissionDenied(err)) // Specific error for authorization failure
			}
		})
	}
}

func TestAuthZMiddleware_SkipChecker(t *testing.T) {
	alwaysSkip := func(req security.Request) bool { return true }
	neverSkip := func(req security.Request) bool { return false }

	mockAuthz := newMockAuthorizer(map[string][]string{
		"/protected.Service/GetData": {"admin"},
	})

	t.Run("SkipChecker allows skipping authorization", func(t *testing.T) {
		tr := newMockTransport("/protected.Service/GetData")
		ctx := transport.NewServerContext(context.Background(), tr)
		// No principal, but should skip
		mw := NewAuthZMiddleware(mockAuthz, WithSkipChecker(alwaysSkip))
		_, err := mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "handler called", nil
		})(ctx, nil)
		assert.NoError(t, err) // Should not error because authorization is skipped
	})

	t.Run("SkipChecker does not skip authorization", func(t *testing.T) {
		tr := newMockTransport("/protected.Service/GetData")
		ctx := transport.NewServerContext(context.Background(), tr)
		// No principal, and should not skip
		mw := NewAuthZMiddleware(mockAuthz, WithSkipChecker(neverSkip))
		_, err := mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "handler called", nil
		})(ctx, nil)
		assert.Error(t, err) // Should error because authorization is not skipped and principal is missing
		assert.True(t, securityv1.IsCredentialsInvalid(err))
	})

	t.Run("PathSkipChecker skips specific path", func(t *testing.T) {
		skipPaths := map[string]bool{
			"/public.Service/GetInfo": true,
		}
		checker := PathSkipChecker(skipPaths)

		// Should skip
		tr := newMockTransport("/public.Service/GetInfo")
		ctx := transport.NewServerContext(context.Background(), tr)
		mw := NewAuthZMiddleware(mockAuthz, WithSkipChecker(checker))
		_, err := mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "handler called", nil
		})(ctx, nil)
		assert.NoError(t, err)

		// Should not skip
		tr = newMockTransport("/protected.Service/GetData")
		ctx = transport.NewServerContext(context.Background(), tr)
		mw = NewAuthZMiddleware(mockAuthz, WithSkipChecker(checker))
		_, err = mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) {
			return "handler called", nil
		})(ctx, nil)
		assert.Error(t, err)
		assert.True(t, securityv1.IsCredentialsInvalid(err))
	})

	t.Run("CompositeSkipChecker combines checkers", func(t *testing.T) {
		checker1 := PathSkipChecker(map[string]bool{"/path1": true})
		checker2 := PathSkipChecker(map[string]bool{"/path2": true})
		composite := CompositeSkipChecker(checker1, checker2)

		// Should skip via checker1
		tr := newMockTransport("/path1")
		ctx := transport.NewServerContext(context.Background(), tr)
		mw := NewAuthZMiddleware(mockAuthz, WithSkipChecker(composite))
		_, err := mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil })(ctx, nil)
		assert.NoError(t, err)

		// Should skip via checker2
		tr = newMockTransport("/path2")
		ctx = transport.NewServerContext(context.Background(), tr)
		mw = NewAuthZMiddleware(mockAuthz, WithSkipChecker(composite))
		_, err = mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil })(ctx, nil)
		assert.NoError(t, err)

		// Should not skip
		tr = newMockTransport("/path3")
		ctx = transport.NewServerContext(context.Background(), tr)
		mw = NewAuthZMiddleware(mockAuthz, WithSkipChecker(composite))
		_, err = mw.Server()(func(ctx context.Context, req interface{}) (interface{}, error) { return "ok", nil })(ctx, nil)
		assert.Error(t, err)
		assert.True(t, securityv1.IsCredentialsInvalid(err))
	})
}
