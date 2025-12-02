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
