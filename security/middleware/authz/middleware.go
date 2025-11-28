package authz

import (
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/contrib/security/request"
	"github.com/origadmin/runtime/context"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware"
)

// Middleware is a Kratos middleware for authorization.
type Middleware struct {
	Authorizer      authz.Authorizer
	SkipChecker     func(security.Request) bool
	PropagationType securityPrincipal.PropagationType
}

// NewAuthZMiddleware creates a new authorization middleware with required skip checker.
// The skipChecker function determines whether authorization should be skipped for a given request.
func NewAuthZMiddleware(a authz.Authorizer, opts ...options.Option) *Middleware {
	o := FromOptions(opts)
	m := &Middleware{
		Authorizer:  a,
		SkipChecker: o.SkipChecker,
	}
	if m.SkipChecker == nil {
		m.SkipChecker = NoOpSkipChecker()
	}
	if o.PropagationType == securityPrincipal.PropagationTypeUnknown {
		o.PropagationType = securityPrincipal.PropagationTypeKratos
	}
	return m
}

// SkipChecker is a function type for determining whether to skip authorization.
type SkipChecker func(security.Request) bool

// PathSkipChecker creates a skip checker that skips authorization for specified paths.
func PathSkipChecker(skipPaths map[string]bool) SkipChecker {
	return func(req security.Request) bool {
		if skipPaths == nil {
			return false
		}
		operation := req.GetOperation()
		return skipPaths[operation]
	}
}

// NoOpSkipChecker creates a skip checker that never skips authorization.
func NoOpSkipChecker() SkipChecker {
	return func(req security.Request) bool {
		return false
	}
}

// CompositeSkipChecker creates a skip checker that combines multiple checkers with OR logic.
func CompositeSkipChecker(checkers ...SkipChecker) SkipChecker {
	return func(req security.Request) bool {
		for _, checker := range checkers {
			if checker(req) {
				return true
			}
		}
		return false
	}
}

// Server implements the Kratos middleware.
func (m *Middleware) Server() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			securityReq, err := request.NewFromServerContext(ctx)
			if err != nil {
				return nil, err
			}

			if m.SkipChecker(securityReq) {
				return handler(ctx, req)
			}

			// Get Principal from context, which should have been set by authn middleware
			principal, ok := securityPrincipal.FromContext(ctx)
			if !ok {
				// No principal found, cannot authorize. This indicates authn middleware was skipped or failed.
				return nil, securityv1.ErrorCredentialsInvalid("principal not found in context")
			}

			// Create a RuleSpec from the security request
			ruleSpec := authz.RuleSpec{
				Resource: securityReq.GetOperation(),
				// Domain and Attributes can be populated from securityReq if available and needed
			}

			// Determine action from HTTP method
			switch securityReq.GetMethod() {
			case "GET", "HEAD", "OPTIONS":
				ruleSpec.Action = "read"
			case "POST":
				ruleSpec.Action = "create"
			case "PUT", "PATCH":
				ruleSpec.Action = "update"
			case "DELETE":
				ruleSpec.Action = "delete"
			default:
				// Fallback or default action if method is unknown or not HTTP (e.g. gRPC)
				// For gRPC, the action might be inferred differently, but for now, we use the operation itself
				// as a reasonable default, which can be handled by specific casbin policies.
				ruleSpec.Action = securityReq.GetOperation()
			}

			// Authorize the principal for the request
			authorized, authzErr := m.Authorizer.Authorized(ctx, principal, ruleSpec)
			if authzErr != nil {
				return nil, authzErr
			}
			if !authorized {
				return nil, securityv1.ErrorPermissionDenied("principal is not authorized for this operation")
			}

			// If authorization succeeds, just proceed. No new context value to inject for authorization status itself.
			return handler(ctx, req)
		}
	}
}

// Client implements the Kratos middleware (optional, for client-side authorization propagation)
func (m *Middleware) Client() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			// Client-side authorization propagation is less common.
			// If needed, logic to propagate authorization context/metadata would go here.
			// For now, it simply passes through.
			return handler(ctx, req)
		}
	}
}
