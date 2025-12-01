/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	casbinv1 "github.com/origadmin/contrib/api/gen/go/security/authz/casbin/v1"
	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/authz/casbin"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

// AuthorizerTestSuite is a test suite for the Authorizer.
type AuthorizerTestSuite struct {
	suite.Suite
	logger log.Logger
	opts   []options.Option
}

// SetupSuite runs once before the entire test suite.
func (s *AuthorizerTestSuite) SetupSuite() {
	s.logger = log.NewStdLogger(os.Stdout)
	s.opts = []options.Option{
		log.WithLogger(s.logger),
	}
}

// TestAuthorizerTestSuite runs the entire test suite.
func TestAuthorizerTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizerTestSuite))
}

// TestDynamicPath tests the authorizer with a custom model definition (sub, obj, act, dom).
func (s *AuthorizerTestSuite) TestDynamicPath() {
	t := s.T()
	cfg := &authzv1.Authorizer{
		Casbin: &casbinv1.Config{
			ModelPath:  "testdata/model_dynamic.conf",
			PolicyPath: "testdata/policy_dynamic.csv",
		},
	}

	auth, err := casbin.NewAuthorizer(cfg, s.opts...)
	require.NoError(t, err)
	require.NotNil(t, auth)

	testCases := []struct {
		name      string
		principal security.Principal
		spec      authz.RuleSpec
		expected  bool
	}{
		{"allow alice to read data1 in domain1", &mockPrincipal{id: "alice"}, authz.RuleSpec{Resource: "data1", Action: "read", Domain: "domain1"}, true},
		{"deny alice to write data1 in domain1", &mockPrincipal{id: "alice"}, authz.RuleSpec{Resource: "data1", Action: "write", Domain: "domain1"}, false},
		{"deny bob to read data1 in domain1", &mockPrincipal{id: "bob"}, authz.RuleSpec{Resource: "data1", Action: "read", Domain: "domain1"}, false},
		{"deny alice to read data1 in domain2", &mockPrincipal{id: "alice"}, authz.RuleSpec{Resource: "data1", Action: "read", Domain: "domain2"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := auth.Authorized(context.Background(), tc.principal, tc.spec)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, allowed)
		})
	}
}

// TestFastPathDomain tests the authorizer with the standard domain model (sub, dom, obj, act).
func (s *AuthorizerTestSuite) TestFastPathDomain() {
	t := s.T()
	cfg := &authzv1.Authorizer{
		Casbin: &casbinv1.Config{
			ModelPath:  "testdata/model_fast_path_domain.conf",
			PolicyPath: "testdata/policy_fast_path_domain.csv",
		},
	}

	auth, err := casbin.NewAuthorizer(cfg, s.opts...)
	require.NoError(t, err)
	require.NotNil(t, auth)

	testCases := []struct {
		name      string
		principal security.Principal
		spec      authz.RuleSpec
		expected  bool
	}{
		{"allow bob to write data2 in domain2", &mockPrincipal{id: "bob"}, authz.RuleSpec{Resource: "data2", Action: "write", Domain: "domain2"}, true},
		{"deny bob to read data2 in domain2", &mockPrincipal{id: "bob"}, authz.RuleSpec{Resource: "data2", Action: "read", Domain: "domain2"}, false},
		{"deny alice to write data2 in domain2", &mockPrincipal{id: "alice"}, authz.RuleSpec{Resource: "data2", Action: "write", Domain: "domain2"}, false},
		{"deny bob to write data2 in domain1", &mockPrincipal{id: "bob"}, authz.RuleSpec{Resource: "data2", Action: "write", Domain: "domain1"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := auth.Authorized(context.Background(), tc.principal, tc.spec)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, allowed)
		})
	}
}

// TestFastPathNonDomain tests the authorizer with the standard non-domain model (sub, obj, act).
func (s *AuthorizerTestSuite) TestFastPathNonDomain() {
	t := s.T()
	cfg := &authzv1.Authorizer{
		Casbin: &casbinv1.Config{
			ModelPath:  "testdata/model_fast_path_non_domain.conf",
			PolicyPath: "testdata/policy_fast_path_non_domain.csv",
		},
	}

	auth, err := casbin.NewAuthorizer(cfg, s.opts...)
	require.NoError(t, err)
	require.NotNil(t, auth)

	testCases := []struct {
		name      string
		principal security.Principal
		spec      authz.RuleSpec
		expected  bool
	}{
		{"allow cindy to delete data3", &mockPrincipal{id: "cindy"}, authz.RuleSpec{Resource: "data3", Action: "delete"}, true},
		{"deny cindy to read data3", &mockPrincipal{id: "cindy"}, authz.RuleSpec{Resource: "data3", Action: "read"}, false},
		{"deny bob to delete data3", &mockPrincipal{id: "bob"}, authz.RuleSpec{Resource: "data3", Action: "delete"}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := auth.Authorized(context.Background(), tc.principal, tc.spec)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, allowed)
		})
	}
}

// TestInitializationEdgeCases tests various initialization scenarios.
func (s *AuthorizerTestSuite) TestInitializationEdgeCases() {
	t := s.T()

	t.Run("should panic for non-existent model file", func(t *testing.T) {
		cfg := &authzv1.Authorizer{
			Casbin: &casbinv1.Config{},
		}
		assert.Panics(t, func() {
			_, _ = casbin.NewAuthorizer(cfg, casbin.WithFileModel("testdata/non_existent_model.conf"))
		})
	})

	t.Run("should panic for invalid model content", func(t *testing.T) {
		cfg := &authzv1.Authorizer{}
		assert.Panics(t, func() {
			_, _ = casbin.NewAuthorizer(cfg, casbin.WithStringModel("[request_definition"))
		})
	})

	t.Run("should create with defaults when config is nil", func(t *testing.T) {
		auth, err := casbin.NewAuthorizer(nil, s.opts...)
		require.NoError(t, err)
		require.NotNil(t, auth)
		allowed, err := auth.Authorized(context.Background(), &mockPrincipal{id: "any"}, authz.RuleSpec{Resource: "any", Action: "any"})
		assert.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("should create with defaults when casbin config is nil", func(t *testing.T) {
		cfg := &authzv1.Authorizer{Casbin: nil}
		auth, err := casbin.NewAuthorizer(cfg, s.opts...)
		require.NoError(t, err)
		require.NotNil(t, auth)
	})
}

// mockPrincipal implements security.Principal for testing.
type mockPrincipal struct {
	id string
}

func (m *mockPrincipal) GetID() string              { return m.id }
func (m *mockPrincipal) GetDomain() string          { return "" }
func (m *mockPrincipal) GetRoles() []string         { return nil }
func (m *mockPrincipal) GetPermissions() []string   { return nil }
func (m *mockPrincipal) GetScopes() map[string]bool { return nil }
func (m *mockPrincipal) GetClaims() security.Claims { return nil }
func (m *mockPrincipal) Export() *securityv1.Principal {
	return &securityv1.Principal{Id: m.id}
}

// TestImplicitDomainWildcard verifies that an empty domain is treated as a wildcard.
func (s *AuthorizerTestSuite) TestImplicitDomainWildcard() {
	t := s.T()
	cfg := &authzv1.Authorizer{
		Casbin: &casbinv1.Config{
			ModelPath:  "testdata/model_fast_path_domain.conf",
			PolicyPath: "testdata/policy_wildcard_domain.csv",
		},
	}

	auth, err := casbin.NewAuthorizer(cfg, s.opts...)
	require.NoError(t, err)
	require.NotNil(t, auth)

	// Scenario 1: 'admin' has access to 'read-only-resource' in ANY domain ('*').
	// We check with an EMPTY domain, expecting it to be treated as a wildcard and return true.
	t.Run("should allow when policy has wildcard and spec has empty domain", func(t *testing.T) {
		spec := authz.RuleSpec{Resource: "read-only-resource", Action: "read", Domain: ""}
		allowed, err := auth.Authorized(context.Background(), &mockPrincipal{id: "admin"}, spec)
		require.NoError(t, err)
		assert.True(t, allowed, "Expected admin to be authorized due to wildcard domain policy")
	})

	// Scenario 2: 'user' has access to 'read-write-resource' ONLY in 'specific-domain'.
	// We check with an EMPTY domain, expecting it to become '*' and NOT match 'specific-domain', returning false.
	t.Run("should deny when policy has specific domain and spec has empty domain", func(t *testing.T) {
		spec := authz.RuleSpec{Resource: "read-write-resource", Action: "write", Domain: ""}
		allowed, err := auth.Authorized(context.Background(), &mockPrincipal{id: "user"}, spec)
		require.NoError(t, err)
		assert.False(t, allowed, "Expected user to be denied as '*' does not match 'specific-domain'")
	})

	// Scenario 3: 'user' has access to 'read-write-resource' ONLY in 'specific-domain'.
	// We check with the CORRECT domain, expecting it to return true.
	t.Run("should allow when policy has specific domain and spec has matching domain", func(t *testing.T) {
		spec := authz.RuleSpec{Resource: "read-write-resource", Action: "write", Domain: "specific-domain"}
		allowed, err := auth.Authorized(context.Background(), &mockPrincipal{id: "user"}, spec)
		require.NoError(t, err)
		assert.True(t, allowed, "Expected user to be authorized with explicit domain match")
	})
}
