package casbin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/origadmin/runtime/interfaces/security"
	securityv1 "github.com/origadmin/contrib/api/gen/go/config/security/v1"
)

// mockPrincipal implements security.Principal for testing purposes.
type mockPrincipal struct {
	id     string
	claims security.Claims
}

// GetID returns the principal's identifier.
func (m *mockPrincipal) GetID() string {
	return m.id
}

// GetRoles returns the roles associated with the principal.
func (m *mockPrincipal) GetRoles() []string {
	roles, _ := m.claims.Get("roles")
	if roles, ok := roles.([]string); ok {
		return roles
	}
	return nil
}

// GetPermissions returns the permissions associated with the principal.
func (m *mockPrincipal) GetPermissions() []string {
	perms, _ := m.claims.Get("permissions")
	if perms, ok := perms.([]string); ok {
		return perms
	}
	return nil
}

// GetScopes returns the scopes associated with the principal.
func (m *mockPrincipal) GetScopes() map[string]bool {
	scopes, _ := m.claims.Get("scopes")
	if scopes, ok := scopes.(map[string]bool); ok {
		return scopes
	}
	return nil
}

// GetClaims returns additional claims associated with the principal.
func (m *mockPrincipal) GetClaims() security.Claims {
	return m.claims
}

// Export implements security.Principal interface.
func (m *mockPrincipal) Export() *securityv1.Principal {
	// Create a new Principal with the ID
	principal := &securityv1.Principal{
		Id: m.id,
	}

	// Add claims if available
	if m.claims != nil {
		// Convert claims to map[string]*structpb.Value
		claims := make(map[string]*structpb.Value)
		for k, v := range m.claims.Export() {
			claims[k] = v
		}
		principal.Claims = claims
	}

	return principal
}

// mockClaims implements security.Claims for testing
type mockClaims struct {
	values map[string]interface{}
}

// Get returns the value associated with the key
func (m *mockClaims) Get(key string) (interface{}, bool) {
	val, ok := m.values[key]
	return val, ok
}

// GetString retrieves a value as a string
func (m *mockClaims) GetString(key string) (string, bool) {
	val, ok := m.values[key]
	if !ok {
		return "", false
	}
	s, ok := val.(string)
	return s, ok
}

// GetInt64 retrieves a value as an int64
func (m *mockClaims) GetInt64(key string) (int64, bool) {
	val, ok := m.values[key]
	if !ok {
		return 0, false
	}
	switch v := val.(type) {
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case string:
		// Implement string to int64 conversion if needed
		return 0, false
	default:
		return 0, false
	}
}

// GetFloat64 retrieves a value as a float64
func (m *mockClaims) GetFloat64(key string) (float64, bool) {
	val, ok := m.values[key]
	if !ok {
		return 0, false
	}
	f, ok := val.(float64)
	return f, ok
}

// GetBool retrieves a value as a bool
func (m *mockClaims) GetBool(key string) (bool, bool) {
	val, ok := m.values[key]
	if !ok {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}

// GetStringSlice retrieves a value as a slice of strings
func (m *mockClaims) GetStringSlice(key string) ([]string, bool) {
	val, ok := m.values[key]
	if !ok {
		return nil, false
	}
	slice, ok := val.([]string)
	if ok {
		return slice, true
	}

	// Handle []interface{} case
	if ifaceSlice, ok := val.([]interface{}); ok {
		result := make([]string, 0, len(ifaceSlice))
		for _, v := range ifaceSlice {
			if s, ok := v.(string); ok {
				result = append(result, s)
			} else {
				return nil, false
			}
		}
		return result, true
	}

	return nil, false
}

// Set sets the value for the given key
func (m *mockClaims) Set(key string, value interface{}) {
	if m.values == nil {
		m.values = make(map[string]interface{})
	}
	m.values[key] = value
}

// Has returns true if the key exists in the claims
func (m *mockClaims) Has(key string) bool {
	_, ok := m.values[key]
	return ok
}

// Delete removes the key from the claims
func (m *mockClaims) Delete(key string) {
	delete(m.values, key)
}

// Keys returns all keys in the claims
func (m *mockClaims) Keys() []string {
	keys := make([]string, 0, len(m.values))
	for k := range m.values {
		keys = append(keys, k)
	}
	return keys
}

// Export converts the claims to a map of *structpb.Value
func (m *mockClaims) Export() map[string]*structpb.Value {
	result := make(map[string]*structpb.Value)
	for k, v := range m.values {
		// Convert the value to *structpb.Value
		if val, err := structpb.NewValue(v); err == nil {
			result[k] = val
		}
	}
	return result
}

// TestEnforcer_Authorize tests the Authorize method of the Casbin Enforcer.
func TestEnforcer_Authorize(t *testing.T) {
	// Create a test model
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

	// Create a temporary file for the model
	modelPath := filepath.Join(t.TempDir(), "model.conf")
	err := os.WriteFile(modelPath, []byte(modelText), 0644)
	require.NoError(t, err)

	// Create test claims
	aliceClaims := &mockClaims{
		values: map[string]interface{}{
			"domain": "domain1",
		},
	}

	// Test cases
	tests := []struct {
		name          string
		setup         func(*Enforcer)
		principal     security.Principal
		resource      string
		action        string
		expected      bool
		expectedError string
	}{
		{
			name: "allowed access",
			setup: func(e *Enforcer) {
				_, _ = e.enforcer.AddPolicy("alice", "domain1", "data1", "read")
			},
			principal: &mockPrincipal{
				id:     "alice",
				claims: aliceClaims,
			},
			resource: "data1",
			action:   "read",
			expected: true,
		},
		{
			name: "denied access",
			setup: func(e *Enforcer) {
				// No policy added for alice:write:data1
			},
			principal: &mockPrincipal{
				id:     "alice",
				claims: aliceClaims,
			},
			resource:      "data1",
			action:        "write",
			expected:      false,
			expectedError: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new enforcer for each test case
			enforcer, err := NewCasbinAuthorizer(
				WithModelPath(modelPath),
				WithDomainField("domain"),
			)
			require.NoError(t, err)

			e, ok := enforcer.(*Enforcer)
			require.True(t, ok)

			// Run setup if provided
			if tt.setup != nil {
				tt.setup(e)
			}

			// Test Authorize
			allowed, err := enforcer.Authorize(context.Background(), tt.principal, tt.resource, tt.action)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, allowed)
			}
		})
	}
}
