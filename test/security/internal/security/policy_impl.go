package security

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/go-kratos/kratos/v2/errors"

	"github.com/origadmin/runtime/interfaces/security/declarative"
	runtimesecurity "github.com/origadmin/runtime/security"
	declarativeimpl "github.com/origadmin/runtime/security/declarative"
)

// --- Example Principal Implementation ---

type examplePrincipal struct {
	id     string
	roles  []string
	claims map[string]interface{}
}

func (p *examplePrincipal) GetID() string {
	return p.id
}

func (p *examplePrincipal) GetRoles() []string {
	return p.roles
}

func (p *examplePrincipal) GetClaims() map[string]interface{} {
	return p.claims
}

// --- ExamplePolicyProvider Implementation (implements declarative.PolicyProvider) ---

// examplePolicyProvider implements the declarative.PolicyProvider interface.
// It manages the mapping from method/path to policy names, and provides
// the actual SecurityPolicy implementations.
type examplePolicyProvider struct {
	// The underlying declarative.Provider which manages policy factories and instances.
	*declarativeimpl.Provider // Embed the core provider for factory and instance management.
	// methodToPolicyName maps gRPC method names or HTTP path templates to policy names.
	methodToPolicyName map[string]string
	mu                 sync.RWMutex
}

// NewPolicyProvider creates a new instance of examplePolicyProvider.
// It initializes the provider with example policy implementations and default policies
// registered via `runtime/security.RegisterPolicies`.
func NewPolicyProvider() declarative.PolicyProvider {
	provider := &examplePolicyProvider{
		Provider:           declarativeimpl.NewProvider(), // Initialize the underlying declarative.Provider
		methodToPolicyName: make(map[string]string),
	}
	provider.registerExamplePolicyFactories()
	// Load default policies from runtime/security
	provider.loadDefaultPolicies()
	return provider
}

// registerExamplePolicyFactories registers the concrete SecurityPolicy implementations as factories.
func (epp *examplePolicyProvider) registerExamplePolicyFactories() {
	epp.Provider.RegisterFactory("public", func(_ []byte) (declarative.SecurityPolicy, error) { return &publicPolicy{}, nil })
	epp.Provider.RegisterFactory("authn-only", func(_ []byte) (declarative.SecurityPolicy, error) { return &authnOnlyPolicy{}, nil })
	epp.Provider.RegisterFactory("authn-authz", func(_ []byte) (declarative.SecurityPolicy, error) { return &authnAuthzPolicy{}, nil })
	fmt.Println("Example security policy factories registered within PolicyProvider.")
}

// loadDefaultPolicies loads the policies registered by generated code into the provider's map.
func (epp *examplePolicyProvider) loadDefaultPolicies() {
	epp.mu.Lock()
	defer epp.mu.Unlock()

	// Get policies for gRPC methods
	for method, policy := range runtimesecurity.GetDefaultServicePolicies() {
		epp.methodToPolicyName[method] = policy
		fmt.Printf("PolicyProvider: Loaded gRPC method '%s' with policy '%s'\n", method, policy)
	}

	// Get policies for HTTP gateway paths
	for path, policy := range runtimesecurity.GetDefaultGatewayPolicies() {
		epp.methodToPolicyName[path] = policy
		fmt.Printf("PolicyProvider: Loaded HTTP path '%s' with policy '%s'\n", path, policy)
	}
	fmt.Println("PolicyProvider: Default policies loaded from runtime/security.")
}

// GetPolicyNameForMethod retrieves the policy name associated with a full gRPC method name or HTTP path.
// It looks up the policy name in its internal map.
func (epp *examplePolicyProvider) GetPolicyNameForMethod(_ context.Context, identifier string) (string, error) {
	epp.mu.RLock()
	defer epp.mu.RUnlock()

	policyName, ok := epp.methodToPolicyName[identifier]
	if !ok {
		// If not found, it might be a method without an explicit policy.
		// The middleware will handle this (e.g., by applying a default policy or denying).
		return "", nil
	}
	return policyName, nil
}

// GetPolicy retrieves the SecurityPolicy implementation for a given policy name by delegating to the embedded Provider.
func (epp *examplePolicyProvider) GetPolicy(ctx context.Context, policyName string) (declarative.SecurityPolicy, error) {
	return epp.Provider.GetPolicy(policyName)
}

// --- Public Policy (No AuthN/AuthZ) ---

type publicPolicy struct{}

// Authenticate always succeeds for public policy.
func (p *publicPolicy) Authenticate(_ context.Context, _ declarative.CredentialSource) (declarative.Principal, error) {
	return &examplePrincipal{id: "anonymous", roles: []string{"guest"}}, nil
}

// Authorize always succeeds for public policy.
func (p *publicPolicy) Authorize(_ context.Context, _ declarative.Principal, _ string) (bool, error) {
	return true, nil
}

// --- AuthnOnly Policy (Authentication only) ---

type authnOnlyPolicy struct{}

// Authenticate checks for a "X-Token" header from the CredentialSource.
func (p *authnOnlyPolicy) Authenticate(_ context.Context, source declarative.CredentialSource) (declarative.Principal, error) {
	token, ok := source.Get("X-Token")
	if !ok || token == "" {
		return nil, errors.Unauthorized("UNAUTHENTICATED", "X-Token header missing")
	}
	if !strings.HasPrefix(token, "Bearer ") {
		return nil, errors.Unauthorized("UNAUTHENTICATED", "Invalid token format")
	}
	// Simulate token validation
	if token == "Bearer valid-user-token" {
		return &examplePrincipal{id: "user-123", roles: []string{"user"}, claims: map[string]interface{}{"token": token}}, nil
	}
	return nil, errors.Unauthorized("UNAUTHENTICATED", "Invalid user token")
}

// Authorize always succeeds for authn-only policy (no specific authorization needed after authentication).
func (p *authnOnlyPolicy) Authorize(_ context.Context, _ declarative.Principal, _ string) (bool, error) {
	return true, nil
}

// --- AuthnAuthz Policy (Authentication + Authorization for 'admin' role) ---

type authnAuthzPolicy struct{}

// Authenticate checks for a "X-Token" header from the CredentialSource.
func (p *authnAuthzPolicy) Authenticate(_ context.Context, source declarative.CredentialSource) (declarative.Principal, error) {
	token, ok := source.Get("X-Token")
	if !ok || token == "" {
		return nil, errors.Unauthorized("UNAUTHENTICATED", "X-Token header missing")
	}
	if !strings.HasPrefix(token, "Bearer ") {
		return nil, errors.Unauthorized("UNAUTHENTICATED", "Invalid token format")
	}
	// Simulate token validation
	if token == "Bearer admin-token" {
		return &examplePrincipal{id: "admin-456", roles: []string{"admin"}, claims: map[string]interface{}{"token": token}}, nil
	}
	// Also allow user token for authentication
	if token == "Bearer valid-user-token" {
		return &examplePrincipal{id: "user-123", roles: []string{"user"}, claims: map[string]interface{}{"token": token}}, nil
	}
	return nil, errors.Unauthorized("UNAUTHENTICATED", "Invalid admin token")
}

// Authorize checks if the principal has the "admin" role.
func (p *authnAuthzPolicy) Authorize(_ context.Context, principal declarative.Principal, _ string) (bool, error) {
	for _, role := range principal.GetRoles() {
		if role == "admin" {
			return true, nil
		}
	}
	return false, errors.Forbidden("FORBIDDEN", "Admin role required")
}
