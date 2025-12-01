package authn

import (
	"context"

	"github.com/go-kratos/kratos/v2/transport"
	"github.com/origadmin/contrib/security" // Import the security package
	"github.com/origadmin/contrib/security/authn"
	securityCredential "github.com/origadmin/contrib/security/credential"
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
			if m.SkipChecker(securityReq) {
				return handler(ctx, req)
			}
			var cred security.Credential
			if tr, ok := transport.FromServerContext(ctx); ok {
				cred, err = securityCredential.ExtractFromTransport(tr)
				if err != nil {
					cred = securityCredential.NewEmptyCredential()
				}
			} else {
				cred = securityCredential.NewEmptyCredential()
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

// Client implements the Kratos middleware for client-side authentication propagation.
func (m *Middleware) Client() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if p, ok := securityPrincipal.FromContext(ctx); ok {
				// Use the helper function for propagation
				ctx = securityPrincipal.PropagatePrincipalToClientContext(ctx, p, m.PropagationType)
			}
			return handler(ctx, req)
		}
	}
}
