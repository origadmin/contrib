package security

import (
	"context"

	"github.com/origadmin/contrib/security"
)

// Authorizer defines the interface for an authorization component.
// It is responsible for determining if a given Principal is authorized to perform
// a specific action on a resource.
type Authorizer interface {
	// Authorize checks if the principal is authorized to perform the action on the resource.
	// It returns true if authorized, false otherwise, and an error if the authorization
	// check itself failed (e.g., due to configuration issues, network problems).
	Authorize(ctx context.Context, p security.Principal, resource, action string) (bool, error)
}
