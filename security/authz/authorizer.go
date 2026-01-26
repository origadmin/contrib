package authz

import (
	"context"

	"github.com/origadmin/contrib/security"
)

// The Authorizer defines the core authorization interface for validating individual requests.
// It is often used as a "goalkeeper" in middleware.
type Authorizer interface {
	// Authorized individual rule specifications are checked.
	Authorized(ctx context.Context, p security.Principal, spec RuleSpec) (bool, error)
}

// Reloader defines an optional interface for authorizers that support dynamic policy reloading.
// This is typically used in conjunction with a policy watcher or an event bus.
type Reloader interface {
	// Reload triggers a reload of the authorization policies from the underlying storage.
	Reload() error
}

// PolicyModifier defines a generic interface for modifying authorization policies at an atomic rule level.
// This abstraction allows business logic to manipulate the fundamental relationships
// (User-Role, Role-Permission) without knowing the underlying implementation (e.g., Casbin, OPA).
type PolicyModifier interface {
	// User-Role Management (Grouping Policies)

	// AddUserRole assigns a role to a user.
	// Returns true if the assignment was added, false if it already existed.
	AddUserRole(ctx context.Context, userID string, roleID string) (bool, error)
	// RemoveUserRole revokes a role from a user.
	// Returns true if the assignment was removed, false if it didn't exist.
	RemoveUserRole(ctx context.Context, userID string, roleID string) (bool, error)
	// RemoveAllUserRoles removes all roles assigned to a specific user.
	// Returns true if any assignments were removed.
	RemoveAllUserRoles(ctx context.Context, userID string) (bool, error)

	// Role-Permission Management (Access Policies)

	// AddRolePermission grants a specific permission to a role.
	// The permission is defined by the RuleSpec (resource and action).
	// Returns true if the permission was added, false if it already existed.
	AddRolePermission(ctx context.Context, roleID string, spec RuleSpec) (bool, error)
	// RemoveRolePermission revokes a specific permission from a role.
	// Returns true if the permission was removed, false if it didn't exist.
	RemoveRolePermission(ctx context.Context, roleID string, spec RuleSpec) (bool, error)
	// RemoveAllRolePermissions removes all permissions granted to a specific role.
	// Returns true if any permissions were removed.
	RemoveAllRolePermissions(ctx context.Context, roleID string) (bool, error)

	// AddUserPermission grants a specific permission directly to a user (less common in pure RBAC, but useful for ABAC or exceptions).
	// Returns true if the permission was added, false if it already existed.
	AddUserPermission(ctx context.Context, userID string, spec RuleSpec) (bool, error)
	// RemoveUserPermission revokes a specific permission directly from a user.
	// Returns true if the permission was removed, false if it didn't exist.
	RemoveUserPermission(ctx context.Context, userID string, spec RuleSpec) (bool, error)
	// RemoveAllUserPermissions removes all direct permissions granted to a specific user.
	// Returns true if any permissions were removed.
	RemoveAllUserPermissions(ctx context.Context, userID string) (bool, error)
}
