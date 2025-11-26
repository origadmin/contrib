package authz

import (
	"context"

	"github.com/origadmin/contrib/security"
)

// RuleSpec encapsulates the specification of an authorization rule to be checked.
// It is a pure data container that describes the core elements required for authorization checks.
type RuleSpec struct {
	Domain   string // Represent the project or tenant. It can be empty.
	Resource string // The resource being accessed.
	Action   string // Actions to be performed on the resource.
	// Attributes contain additional attributes related to this rule, such as the owner of the resource, status, and so on.
	// This allows RuleSpec to carry more complex contextual information to support ABAC.
	Attributes security.Claims
}

// The Authorizer defines the core authorization interface for validating individual requests.
// It is often used as a "goalkeeper" in middleware.
type Authorizer interface {
	// Authorized individual rule specifications are checked.
	Authorized(ctx context.Context, p security.Principal, spec RuleSpec) (bool, error)
}
