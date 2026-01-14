package authz

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security/request"
	"github.com/origadmin/contrib/security/skip"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware"
)

// Middleware is a Kratos middleware for authorization.
type Middleware struct {
	*Options
	log *log.Helper
}

// New is a convenience function for creating a new authorization middleware for manual use.
func New(authorizer authz.Authorizer, opts ...options.Option) *Middleware {
	allOpts := append([]options.Option{WithAuthorizer(authorizer)}, opts...)
	o := fromOptions(allOpts)
	return newMiddleware(o)
}

// newMiddleware is the internal constructor that takes a pre-parsed options struct.
func newMiddleware(opts *Options) *Middleware {
	m := &Middleware{
		Options: opts,
		log:     log.NewHelper(log.With(opts.Logger, "module", "security.middleware.authz")),
	}
	if m.Skipper == nil {
		m.Skipper = skip.Noop()
	}
	return m
}

// Server implements the Kratos middleware.
func (m *Middleware) Server() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			securityReq, err := request.NewFromServerContext(ctx)
			if err != nil {
				m.log.WithContext(ctx).Errorf("[AuthZ] Failed to create security request from context: %v", err)
				return nil, err
			}

			if m.Skipper(ctx, securityReq) {
				m.log.WithContext(ctx).Debugf("[AuthZ] Skipped for operation: %s", securityReq.GetOperation())
				return handler(ctx, req)
			}

			principal, ok := security.FromContext(ctx)
			if !ok {
				// This is a critical failure if we've reached the authorization stage.
				m.log.WithContext(ctx).Warnf("[AuthZ] Principal not found in context for operation %s, denying access.", securityReq.GetOperation())
				return nil, securityv1.ErrorCredentialsInvalid("principal not found in context")
			}

			ruleSpec := authz.NewRuleSpec(principal, securityReq)
			// This is the most critical log for debugging permissions.
			m.log.WithContext(ctx).Debugf("[AuthZ] Checking: Principal=%s, Domain=%s, Resource=%s, Action=%s", principal.GetID(), ruleSpec.Domain, ruleSpec.Resource, ruleSpec.Action)

			authorized, authzErr := m.Authorizer.Authorized(ctx, principal, ruleSpec)
			if authzErr != nil {
				m.log.WithContext(ctx).Errorf("[AuthZ] Authorizer returned an error: %v", authzErr)
				return nil, authzErr
			}
			if !authorized {
				// This is a standard denial, should be a debug or info log, not a warning.
				m.log.WithContext(ctx).Debugf("[AuthZ] Denied access for Principal ID: %s", principal.GetID())
				return nil, securityv1.ErrorPermissionDenied("principal is not authorized for this operation")
			}

			// This log is mostly noise if everything is working.
			// m.log.WithContext(ctx).Debugf("[AuthZ] Granted access for Principal ID: %s", principal.GetID())
			return handler(ctx, req)
		}
	}
}

// Client implements the Kratos middleware.
func (m *Middleware) Client() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			return handler(ctx, req)
		}
	}
}
