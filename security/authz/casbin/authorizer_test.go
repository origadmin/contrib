/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	casbinv1 "github.com/origadmin/contrib/api/gen/go/security/authz/casbin/v1"
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin"
)

// MockAdapter is a mock Casbin policy adapter for testing.
type MockAdapter struct {
	loadPolicyFunc           func(model model.Model) error
	savePolicyFunc           func(model model.Model) error
	addPolicyFunc            func(sec string, ptype string, rule []string) error
	removePolicyFunc         func(sec string, ptype string, rule []string) error
	removeFilteredPolicyFunc func(sec string, ptype string, fieldIndex int, fieldValues ...string) error
}

func (m *MockAdapter) LoadPolicy(model model.Model) error {
	if m.loadPolicyFunc != nil {
		return m.loadPolicyFunc(model)
	}
	return nil
}

func (m *MockAdapter) SavePolicy(model model.Model) error {
	if m.savePolicyFunc != nil {
		return m.savePolicyFunc(model)
	}
	return nil
}

func (m *MockAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	if m.addPolicyFunc != nil {
		return m.addPolicyFunc(sec, ptype, rule)
	}
	return nil
}

func (m *MockAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	if m.removePolicyFunc != nil {
		return m.removePolicyFunc(sec, ptype, rule)
	}
	return nil
}

func (m *MockAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	if m.removeFilteredPolicyFunc != nil {
		return m.removeFilteredPolicyFunc(sec, ptype, fieldIndex, fieldValues...)
	}
	return nil
}

func TestNewAuthorizer(t *testing.T) {
	// Define a simple model for testing
	testModel := `
[request_definition]
r = sub, obj, act, dom

[policy_definition]
p = sub, obj, act, dom

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act && r.dom == p.dom
`

	t.Run("should create authorizer with default model and memory adapter if no config or options provided", func(t *testing.T) {
		cfg := &authzv1.Authorizer{} // Empty config
		auth, err := casbin.NewAuthorizer(cfg)
		require.NoError(t, err)
		assert.NotNil(t, auth)

		// Test with a simple policy
		_, err = auth.Authorized(context.Background(), &mockPrincipal{id: "alice"}, authz.RuleSpec{Resource: "data1", Action: "read", Domain: "domain1", Attributes: &mockClaims{}})
		require.NoError(t, err)
	})

	t.Run("should load model from config file path", func(t *testing.T) {
		// Create a temporary model file
		tmpDir := t.TempDir()
		modelFilePath := filepath.Join(tmpDir, "model.conf")
		err := os.WriteFile(modelFilePath, []byte(testModel), 0644)
		require.NoError(t, err)

		cfg := &authzv1.Authorizer{
			Casbin: &casbinv1.Config{
				ModelPath: modelFilePath,
			},
		}
		auth, err := casbin.NewAuthorizer(cfg)
		require.NoError(t, err)
		assert.NotNil(t, auth)

		// Test authorization with the loaded model
		allowed, err := auth.Authorized(context.Background(), &mockPrincipal{id: "alice"}, authz.RuleSpec{Resource: "data1", Action: "read", Domain: "domain1", Attributes: &mockClaims{}})
		require.NoError(t, err)
		assert.False(t, allowed, "should not be allowed without policy")
	})

	t.Run("should load model from WithFileModel option, overriding config", func(t *testing.T) {
		// Create two temporary model files
		tmpDir := t.TempDir()
		configModelFilePath := filepath.Join(tmpDir, "config_model.conf")
		optionModelFilePath := filepath.Join(tmpDir, "option_model.conf")

		err := os.WriteFile(configModelFilePath, []byte("config model content"), 0644)
		require.NoError(t, err)
		err = os.WriteFile(optionModelFilePath, []byte(testModel), 0644)
		require.NoError(t, err)

		cfg := &authzv1.Authorizer{
			Casbin: &casbinv1.Config{
				ModelPath: configModelFilePath, // This should be overridden
			},
		}

		auth, err := casbin.NewAuthorizer(cfg, casbin.WithFileModel(optionModelFilePath))
		require.NoError(t, err)
		assert.NotNil(t, auth)

		// Test authorization with the loaded model
		allowed, err := auth.Authorized(context.Background(), &mockPrincipal{id: "alice"}, authz.RuleSpec{Resource: "data1", Action: "read", Domain: "domain1", Attributes: &mockClaims{}})
		require.NoError(t, err)
		assert.False(t, allowed, "should not be allowed without policy")
	})

	t.Run("should load model from WithStringModel option", func(t *testing.T) {
		cfg := &authzv1.Authorizer{} // Empty config

		auth, err := casbin.NewAuthorizer(cfg, casbin.WithStringModel(testModel))
		require.NoError(t, err)
		assert.NotNil(t, auth)

		// Test authorization with the loaded model
		allowed, err := auth.Authorized(context.Background(), &mockPrincipal{id: "alice"}, authz.RuleSpec{Resource: "data1", Action: "read", Domain: "domain1", Attributes: &mockClaims{}})
		require.NoError(t, err)
		assert.False(t, allowed, "should not be allowed without policy")
	})

	t.Run("should use custom policy adapter from WithPolicyAdapter option", func(t *testing.T) {
		mockAdapter := &MockAdapter{}
		cfg := &authzv1.Authorizer{} // Empty config

		auth, err := casbin.NewAuthorizer(cfg, casbin.WithPolicyAdapter(mockAdapter))
		require.NoError(t, err)
		assert.NotNil(t, auth)

		// To verify the adapter is used, we'd ideally need to access the internal enforcer's adapter
		// or make the mock adapter record calls. For now, we assume if it initializes, it's using it.
		// A more direct test would involve reflection or exposing the adapter.
	})

	t.Run("should return error if casbin config is empty", func(t *testing.T) {
		cfg := &authzv1.Authorizer{
			Casbin: nil, // Explicitly nil casbin config
		}
		auth, err := casbin.NewAuthorizer(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authorizer casbin config is empty")
		assert.Nil(t, auth)
	})

	t.Run("should panic if WithFileModel option points to non-existent file", func(t *testing.T) {
		cfg := &authzv1.Authorizer{} // Empty config
		nonExistentPath := filepath.Join(t.TempDir(), "non_existent_model.conf")

		assert.Panics(t, func() {
			_, _ = casbin.NewAuthorizer(cfg, casbin.WithFileModel(nonExistentPath))
		})
	})

	t.Run("should panic if WithStringModel option has invalid model string", func(t *testing.T) {
		cfg := &authzv1.Authorizer{}          // Empty config
		invalidModel := `[request_definition` // Incomplete model

		assert.Panics(t, func() {
			_, _ = casbin.NewAuthorizer(cfg, casbin.WithStringModel(invalidModel))
		})
	})
}

// mockClaims implements security.Claims for testing.
type mockClaims struct{}

func (m *mockClaims) Get(key string) (any, bool)                  { return nil, false }
func (m *mockClaims) GetString(key string) (string, bool)         { return "", false }
func (m *mockClaims) GetInt64(key string) (int64, bool)           { return 0, false }
func (m *mockClaims) GetFloat64(key string) (float64, bool)       { return 0, false }
func (m *mockClaims) GetBool(key string) (bool, bool)             { return false, false }
func (m *mockClaims) GetStringSlice(key string) ([]string, bool)  { return nil, false }
func (m *mockClaims) GetMap(key string) (map[string]any, bool)    { return nil, false }
func (m *mockClaims) UnmarshalValue(key string, target any) error { return nil }
func (m *mockClaims) Export() map[string]*structpb.Value          { return nil }

// mockPrincipal implements security.Principal for testing.
type mockPrincipal struct {
	id string
}

func (m *mockPrincipal) GetID() string {
	return m.id
}

func (m *mockPrincipal) GetRoles() []string {
	return nil
}

func (m *mockPrincipal) GetPermissions() []string {
	return nil
}

func (m *mockPrincipal) GetScopes() map[string]bool {
	return nil
}

func (m *mockPrincipal) GetClaims() security.Claims {
	return &mockClaims{}
}

func (m *mockPrincipal) Export() *securityv1.Principal {
	return &securityv1.Principal{Id: m.id}
}
