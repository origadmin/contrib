package authz

import (
	"context"

	"github.com/origadmin/contrib/security"
	securityPrincipal "github.com/origadmin/contrib/security/principal" // Import principal package to get Principal from context
)

// Define standard authorization actions as constants.
const (
	ActionRead   = "read"
	ActionCreate = "create"
	ActionUpdate = "update" // Corrected from "create" to "update"
	ActionDelete = "delete"
)

// NewRuleSpecFromContextAndSecurityRequest creates an authz.RuleSpec from a context and security.Request.
// It maps HTTP methods to standard authorization actions (read, create, update, delete).
// If the method does not match a standard action, the operation itself is used as the action.
// The Domain is extracted from the Principal found in the context.
func NewRuleSpecFromContextAndSecurityRequest(ctx context.Context, req security.Request) RuleSpec {
	ruleSpec := RuleSpec{
		Resource: req.GetOperation(),
	}

	// Extract Principal from context to get the Domain
	if p, ok := securityPrincipal.FromContext(ctx); ok {
		ruleSpec.Domain = p.GetDomain()
	}

	switch req.GetMethod() {
	case "GET", "HEAD", "OPTIONS":
		ruleSpec.Action = ActionRead
	case "POST":
		ruleSpec.Action = ActionCreate
	case "PUT", "PATCH":
		ruleSpec.Action = ActionUpdate
	case "DELETE":
		ruleSpec.Action = ActionDelete
	default:
		ruleSpec.Action = req.GetOperation()
	}
	return ruleSpec
}
