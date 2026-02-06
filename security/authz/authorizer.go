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

// PolicyModifier defines a generic, pattern-based interface for modifying authorization policies.
// It is implementation-agnostic (Casbin, OPA, etc.) and uses a "Query by Example" style for removals.
//
// Field Semantics:
// - String fields ("", "") act as wildcards (match any value)
// - repeated string fields (nil, []) act as wildcards (match any value)
// - optional fields (nil) act as wildcards (match any value)
type PolicyModifier interface {
	// AddPolicies adds one or more policies.
	AddPolicies(ctx context.Context, policies ...*authzv1.PolicySpec) (bool, error)

	// UpdatePolicies updates policies in batch.
	// The oldPolicies and newPolicies arrays must have the same length.
	// Each oldPolicies[i] is matched by type+subject+domain+actions+resources combination
	// and replaced with newPolicies[i].
	UpdatePolicies(ctx context.Context, oldPolicies []*authzv1.PolicySpec, newPolicies []*authzv1.PolicySpec) (bool,
		error)

	// RemovePolicies removes policies matching the pattern (Query by Example).
	// Zero-value fields in the pattern act as wildcards.
	// Examples:
	// - RemovePolicies(ctx, PolicySpec{Subject: "user1"}): Removes all policies for user1
	// - RemovePolicies(ctx, PolicySpec{Domain: "d1"}): Removes all policies in domain d1
	// - RemovePolicies(ctx, PolicySpec{}): Removes all policies
	RemovePolicies(ctx context.Context, pattern *authzv1.PolicySpec) (bool, error)

	// ClearPolicies removes all policies for the given subjects.
	// This is a comprehensive cleanup operation that removes all policy types.
	// Examples:
	// - ClearPolicies(ctx, "user1"): Removes all policies for user1 across all domains.
	// - ClearPolicies(ctx): Removes all policies for all subjects across all domains.
	ClearPolicies(ctx context.Context, subjects ...string) (bool, error)

	// Deprecated: Use AddPolicies with PolicySpec instead.
	AddRoles(ctx context.Context, subject string, roles ...RoleSpec) (bool, error)

	// Deprecated: Use RemovePolicies with PolicySpec instead.
	RemoveRoles(ctx context.Context, subject string, roles ...RoleSpec) (bool, error)

	// Deprecated: Use UpdatePolicies with PolicySpec instead.
	UpdateRole(ctx context.Context, subject string, oldRole RoleSpec, newRole RoleSpec) (bool, error)

	// Deprecated: Use AddPolicies with PolicySpec instead.
	AddPermissions(ctx context.Context, subject string, permissions ...RuleSpec) (bool, error)

	// Deprecated: Use RemovePolicies with PolicySpec instead.
	RemovePermissions(ctx context.Context, subject string, permissions ...RuleSpec) (bool, error)

	// Deprecated: Use UpdatePolicies with PolicySpec instead.
	UpdatePermission(ctx context.Context, subject string, oldPerm RuleSpec, newPerm RuleSpec) (bool, error)
}
