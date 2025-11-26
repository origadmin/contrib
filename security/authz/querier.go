package authz

import (
	"context"

	"github.com/origadmin/contrib/security"
)

// PermissionQuerier defines the interface for querying permissions in batches.
// Its primary consumer is API endpoints that need to perform bulk permission checks,
// for example, to filter a list of items based on the user's access rights.
type PermissionQuerier interface {
	// FilterAuthorized is the generic and powerful core method of this interface.
	// It filters a list of RuleSpecs and returns the subset for which the principal is authorized.
	// It is useful for complex, non-standard batch filtering scenarios.
	FilterAuthorized(ctx context.Context, p security.Principal, specs []RuleSpec) ([]RuleSpec, error)

	// FilterAuthorizedResources is a convenience method for the common use case of filtering a list of resource IDs.
	// It abstracts away the complexity of creating and parsing RuleSpecs.
	// The specTemplate provides a template for the check, where its Resource field is ignored.
	FilterAuthorizedResources(ctx context.Context, p security.Principal, specTemplate RuleSpec, resources []string) ([]string, error)

	// FilterAuthorizedActions is a convenience method to determine which actions a principal can perform on a given resource.
	// The specTemplate provides a template for the check, where its Action field is ignored.
	FilterAuthorizedActions(ctx context.Context, p security.Principal, specTemplate RuleSpec, actions []string) ([]string, error)

	// FilterAuthorizedDomains is a convenience method to determine which domains a principal has access to.
	// The specTemplate provides a template for the check, where its Domain field is ignored.
	FilterAuthorizedDomains(ctx context.Context, p security.Principal, specTemplate RuleSpec, domains []string) ([]string, error)
}
