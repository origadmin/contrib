package casbin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	authzFactory "github.com/origadmin/contrib/security/authz"
	securityifaces "github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/contrib/security/request"
)

func createTestProvider(t *testing.T, model string, adapter persist.Adapter) authzFactory.Provider {
	securityConfig := &securityv1.Security{
		Authz: &securityv1.Authorizer{
			Type: "casbin",
			Config: &securityv1.Authorizer_Casbin{
				Casbin: &casbinv1.Config{
					Model: model,
				},
			},
		},
	}

	provider, err := authzFactory.Create(securityConfig, WithAdapter(adapter))
	require.NoError(t, err)
	require.NotNil(t, provider)
	return provider
}

func TestCasbinAuthorizer_Success(t *testing.T) {
	adapter := NewMemoryAdapter()
	provider := createTestProvider(t, DefaultModel, adapter)
	authorizer, ok := provider.Authorizer()
	require.True(t, ok)

	// Add policy: alice can read data1 in domain1
	_, err := authorizer.(*Authorizer).enforcer.AddPolicy("alice", "domain1", "/data1", "GET")
	require.NoError(t, err)

	// Create principal and request
	claims, _ := principal.NewClaims(map[string]interface{}{"tenant_id": "domain1"})
	p := principal.New("alice", nil, nil, nil, claims)
	req := request.New("/data1", "GET")

	// Authorize
	allowed, err := authorizer.Authorized(context.Background(), p, req)
	assert.NoError(t, err)
	assert.True(t, allowed)
}

func TestCasbinAuthorizer_Denied(t *testing.T) {
	adapter := NewMemoryAdapter()
	provider := createTestProvider(t, DefaultModel, adapter)
	authorizer, ok := provider.Authorizer()
	require.True(t, ok)

	// Add policy: alice can read data1 in domain1
	_, err := authorizer.(*Authorizer).enforcer.AddPolicy("alice", "domain1", "/data1", "GET")
	require.NoError(t, err)

	// Create principal and request for a different action
	claims, _ := principal.NewClaims(map[string]interface{}{"tenant_id": "domain1"})
	p := principal.New("alice", nil, nil, nil, claims)
	req := request.New("/data1", "POST")

	// Authorize
	allowed, err := authorizer.Authorized(context.Background(), p, req)
	assert.Error(t, err)
	assert.False(t, allowed)
	assert.True(t, securityv1.IsPermissionDenied(err))
}
