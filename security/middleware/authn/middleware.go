package authn

import (
	"context"

	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/credential"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/contrib/security/request"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware"
)

// Middleware is a Kratos middleware for authentication.
// It embeds the Options struct to hold its configuration.
type Middleware struct {
	*Options
}

// New is a convenience function for creating a new authentication middleware for manual use.
func New(authenticator authn.Authenticator, opts ...options.Option) *Middleware {
	allOpts := append([]options.Option{WithAuthenticator(authenticator)}, opts...)
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
			if _, ok := securityPrincipal.FromContext(ctx); ok {
				return handler(ctx, req)
			}
			securityReq, err := request.NewFromServerContext(ctx)
			if err != nil {
				return nil, err
			}
			if m.SkipChecker(ctx, securityReq) {
				return handler(ctx, req)
			}

			// Extract credential using the package-level function
			cred, err := credential.ExtractFromRequest(ctx, securityReq)
			if err != nil {
				// If credential extraction fails, return the error immediately.
				return nil, err
			}

			principal, authErr := m.Authenticator.Authenticate(ctx, cred)
			if authErr != nil {
				return nil, authErr
			}
			ctx = securityPrincipal.NewContext(ctx, principal)
			return handler(ctx, req)
		}
	}
}

// Client implements the Kratos middleware. After refactoring, this is a no-op.
// Principal propagation is now handled by the dedicated principal middleware.
func (m *Middleware) Client() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			return handler(ctx, req)
		}
	}
}
