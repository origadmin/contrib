package authz

import (
	"context"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/contrib/security/request"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware"
)

// Middleware is a Kratos middleware for authorization.
// It embeds the Options struct to hold its configuration.
type Middleware struct {
	*Options
}

// New is a convenience function for creating a new authorization middleware for manual use.
func New(authorizer authz.Authorizer, opts ...options.Option) *Middleware {
	allOpts := append([]options.Option{WithAuthorizer(authorizer)}, opts...)
	o := fromOptions(allOpts...)
	return newMiddleware(o)
}

// newMiddleware is the internal constructor that takes a pre-parsed options struct.
func newMiddleware(opts *Options) *Middleware {
	m := &Middleware{
		Options: opts,
	}
	// Use the common NoOpSkipChecker if none is provided
	if m.SkipChecker == nil {
		m.SkipChecker = security.NoOpSkipChecker()
	}
	return m
}

// Server implements the Kratos middleware.
func (m *Middleware) Server() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			securityReq, err := request.NewFromServerContext(ctx)
			if err != nil {
				return nil, err
			}
			// Use the embedded SkipChecker
			if m.SkipChecker(ctx, securityReq) {
				return handler(ctx, req)
			}
			principal, ok := securityPrincipal.FromContext(ctx)
			if !ok {
				return nil, securityv1.ErrorCredentialsInvalid("principal not found in context")
			}
			// Create the rule specification from the principal and request.
			ruleSpec := authz.NewRuleSpec(principal, securityReq)

			authorized, authzErr := m.Authorizer.Authorized(ctx, principal, ruleSpec)
			if authzErr != nil {
				return nil, authzErr
			}
			if !authorized {
				return nil, securityv1.ErrorPermissionDenied("principal is not authorized for this operation")
			}
			return handler(ctx, req)
		}
	}
}

// Client implements the Kratos middleware. For authorization, this is typically a no-op.
func (m *Middleware) Client() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			return handler(ctx, req)
		}
	}
}
