package authn

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/credential"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/contrib/security/request"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware"
)

// Middleware is a Kratos middleware for authentication.
type Middleware struct {
	*Options
	log *log.Helper
}

// New is a convenience function for creating a new authentication middleware for manual use.
func New(authenticator authn.Authenticator, opts ...options.Option) *Middleware {
	allOpts := append([]options.Option{WithAuthenticator(authenticator)}, opts...)
	o := fromOptions(allOpts)
	return newMiddleware(o)
}

// newMiddleware is the internal constructor that takes a pre-parsed options struct.
func newMiddleware(opts *Options) *Middleware {
	m := &Middleware{
		Options: opts,
		log:     log.NewHelper(opts.Logger),
	}
	if m.SkipChecker == nil {
		m.SkipChecker = security.NoOpSkipChecker()
	}
	return m
}

// Server implements the Kratos middleware.
func (m *Middleware) Server() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if _, ok := securityPrincipal.FromContext(ctx); ok {
				// This is a normal case if propagation middleware ran first. No log needed.
				return handler(ctx, req)
			}

			securityReq, err := request.NewFromServerContext(ctx)
			if err != nil {
				m.log.WithContext(ctx).Errorf("[AuthN] Failed to create security request from context: %v", err)
				return nil, err
			}

			if m.SkipChecker(ctx, securityReq) {
				m.log.WithContext(ctx).Debugf("[AuthN] Skipped for operation: %s", securityReq.GetOperation())
				return handler(ctx, req)
			}

			cred, err := credential.ExtractFromRequest(ctx, securityReq)
			if err != nil {
				// This is an expected error for unauthenticated requests, should not be a warning.
				m.log.WithContext(ctx).Debugf("[AuthN] Credential extraction failed for operation %s: %v", securityReq.GetOperation(), err)
				return nil, err
			}

			principal, authErr := m.Authenticator.Authenticate(ctx, cred)
			if authErr != nil {
				// This is a critical failure path, a Warn is appropriate.
				m.log.WithContext(ctx).Warnf("[AuthN] Authentication failed for operation %s: %v", securityReq.GetOperation(), authErr)
				return nil, authErr
			}

			ctx = securityPrincipal.NewContext(ctx, principal)
			m.log.WithContext(ctx).Debugf("[AuthN] Authentication successful, principal injected: ID=%s", principal.GetID())
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
