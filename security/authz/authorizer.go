package authz

import (
	"context"

	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	"github.com/origadmin/contrib/security"
)

// The Authorizer defines the core authorization interface for validating individual requests.
type Authorizer interface {
	Authorized(ctx context.Context, p security.Principal, spec RuleSpec) (bool, error)
}

// Reloader defines an optional interface for authorizers that support dynamic policy reloading.
type Reloader interface {
	// Reload forces the authorizer to reload its policies from the underlying storage.
	// The 'force' parameter is crucial:
	// - If force is true, the reload must happen regardless of whether a watcher is configured.
	// - If force is false, the implementation may choose to skip the reload if a watcher
	//   is active, assuming the watcher will handle updates.
	Reload(force bool) error
}

// PolicyReader defines the read-only interface for querying policies.
type PolicyReader interface {
	// ListPolicies queries policies matching the filter criteria.
	// The filter can be constructed from a PolicySpec and/or PolicyFilterOption(s).
	// Examples:
	// - ListPolicies(ctx, nil, WithFilterSubject("user1")): List all policies for user1
	// - ListPolicies(ctx, &authzv1.PolicySpec{Domain: ptr("d1")}): List all policies in domain d1
	// - ListPolicies(ctx, &authzv1.PolicySpec{Type: "rbac:role"}, WithFilterDomain("d1")): Combine
	ListPolicies(ctx context.Context, base *authzv1.PolicySpec, opts ...PolicyFilterOption) ([]*authzv1.PolicySpec, error)
}

// PolicyWriter defines the write interface for modifying policies.
type PolicyWriter interface {
	// AddPolicies adds one or more policies.
	AddPolicies(ctx context.Context, policies ...*authzv1.PolicySpec) (bool, error)

	// UpdatePolicies updates policies in batch.
	// The oldPolicies and newPolicies arrays must have the same length.
	// Each oldPolicies[i] is matched and replaced with newPolicies[i].
	UpdatePolicies(ctx context.Context, oldPolicies []*authzv1.PolicySpec, newPolicies []*authzv1.PolicySpec) (bool, error)

	// RemovePolicies removes policies matching the filter criteria.
	// The filter can be constructed from a PolicySpec and/or PolicyFilterOption(s).
	// Examples:
	// - RemovePolicies(ctx, nil, WithFilterSubject("user1")): Remove all policies for user1
	// - RemovePolicies(ctx, &authzv1.PolicySpec{Domain: ptr("d1")}): Remove all policies in domain d1
	RemovePolicies(ctx context.Context, base *authzv1.PolicySpec, opts ...PolicyFilterOption) (bool, error)

	// ClearPolicies removes all policies.
	ClearPolicies(ctx context.Context) (bool, error)
}

// PolicyModifier combines PolicyReader and PolicyWriter for full CRUD operations.
// Deprecated: Use PolicyReader and PolicyWriter separately for better control over access permissions.
type PolicyModifier interface {
	PolicyReader
	PolicyWriter

	// Deprecated: Use AddPolicies with PolicySpec instead.
	AddRoles(ctx context.Context, subject string, roles ...RoleSpec) (bool, error)

	// Deprecated: Use RemovePolicies with PolicySpec and PolicyFilterOption instead.
	RemoveRoles(ctx context.Context, subject string, roles ...RoleSpec) (bool, error)

	// Deprecated: Use UpdatePolicies with PolicySpec instead.
	UpdateRole(ctx context.Context, subject string, oldRole RoleSpec, newRole RoleSpec) (bool, error)

	// Deprecated: Use AddPolicies with PolicySpec instead.
	AddPermissions(ctx context.Context, subject string, permissions ...RuleSpec) (bool, error)

	// Deprecated: Use RemovePolicies with PolicySpec and PolicyFilterOption instead.
	RemovePermissions(ctx context.Context, subject string, permissions ...RuleSpec) (bool, error)

	// Deprecated: Use UpdatePolicies with PolicySpec instead.
	UpdatePermission(ctx context.Context, subject string, oldPerm RuleSpec, newPerm RuleSpec) (bool, error)
}

// Helper function for creating string pointers (used with PolicySpec optional fields)
func strPtr(s string) *string {
	return &s
}
