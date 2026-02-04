package authz

import (
	"context"

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
type PolicyModifier interface {
	// AddRoles assigns one or more roles to a subject.
	AddRoles(ctx context.Context, subject string, roles ...RoleSpec) (bool, error)

	// RemoveRoles revokes roles from a subject based on patterns.
	// - RemoveRoles(ctx, "user1"): Removes all roles from user1 across all domains.
	// - RemoveRoles(ctx, "user1", RoleSpec{Domain: "d1"}): Removes all roles from user1 within domain d1.
	// - RemoveRoles(ctx, "user1", RoleSpec{Role: "admin"}): Removes the "admin" role from user1 across all domains.
	// - RemoveRoles(ctx, "user1", RoleSpec{Role: "admin", Domain: "d1"}): Removes the specific role-domain assignment.
	RemoveRoles(ctx context.Context, subject string, roles ...RoleSpec) (bool, error)

	// UpdateRole updates a single role assignment for a subject.
	// This is an atomic operation that replaces the old role specification with the new one.
	UpdateRole(ctx context.Context, subject string, oldRole RoleSpec, newRole RoleSpec) (bool, error)

	// AddPermissions grants one or more permissions to a subject.
	AddPermissions(ctx context.Context, subject string, permissions ...RuleSpec) (bool, error)

	// RemovePermissions revokes permissions from a subject based on patterns.
	// The logic mirrors RemoveRoles, using the fields of RuleSpec as filters.
	// An empty or zero-value field in a RuleSpec acts as a wildcard.
	RemovePermissions(ctx context.Context, subject string, permissions ...RuleSpec) (bool, error)

	// UpdatePermission updates a single permission grant for a subject.
	// This is an atomic operation that replaces the old permission specification with the new one.
	UpdatePermission(ctx context.Context, subject string, oldPerm RuleSpec, newPerm RuleSpec) (bool, error)

	// ClearPolicies removes all policies (both roles and permissions) for a subject.
	// This is a comprehensive cleanup operation that removes:
	// - All role assignments (g-rules) for the subject
	// - All permission grants (p-rules) for the subject
	// Use with caution: this cannot be undone.
	// Examples:
	// - ClearPolicies(ctx, "user1"): Removes all policies for user1 across all domains.
	// - ClearPolicies(ctx): Removes all policies for all subjects across all domains.
	ClearPolicies(ctx context.Context, subjects ...string) (bool, error)
}
