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

// NewRuleSpec creates an authz.RuleSpec from a principal and a security.Request.
// It maps HTTP methods to standard authorization actions (read, create, update, delete).
func NewRuleSpec(p security.Principal, req security.Request) RuleSpec {
	ruleSpec := RuleSpec{
		Resource: req.GetOperation(),
	}

	if p != nil {
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
		// Fallback to the operation name if the HTTP method is not standard.
		ruleSpec.Action = req.GetOperation()
	}
	return ruleSpec
}
