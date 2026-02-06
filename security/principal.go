package security

import (
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
)

// Principal represents the identity of the entity making a request.
// It typically contains information about the authenticated user or service.
type Principal interface {
	// GetID returns the unique identifier of the principal.
	GetID() string
	// GetDomain returns the domain associated with the principal.
	// This is often used in multi-tenant or multi-project environments.
	GetDomain() string
	// GetRoles returns a slice of roles assigned to the principal.
	GetRoles() []string
	// GetPermissions returns a slice of permissions granted to the principal.
	GetPermissions() []string
	// GetScopes returns a map of scopes associated with the principal.
	GetScopes() map[string]bool
	// GetClaims returns the custom claims associated with the principal.
	GetClaims() Claims
	// Export converts the Principal to its Protobuf representation.
	Export() *securityv1.Principal
}
