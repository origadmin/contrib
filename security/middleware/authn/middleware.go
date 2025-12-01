package authn

import (
	"context"

	"github.com/go-kratos/kratos/v2/transport"

	"github.com/origadmin/contrib/security"
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
			if m.SkipChecker(ctx, securityReq) {
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

// Client implements the Kratos middleware for client-side principal propagation.
// It extracts the Principal from the context, encodes it, and injects it into the
// outgoing request's metadata (for gRPC) or headers (for HTTP).
func (m *Middleware) Client() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			// 1. Attempt to extract the Principal from the current context.
			p, ok := securityPrincipal.FromContext(ctx)
			if !ok {
				// If no Principal is found, proceed without adding any headers.
				return handler(ctx, req)
			}

			// 2. Encode the Principal into a string format suitable for transport.
			encodedPrincipal, err := securityPrincipal.Encode(p)
			if err != nil {
				// If encoding fails, it's a critical internal error.
				return nil, err
			}

			// 3. Inject the encoded Principal into the outgoing request context.
			newCtx := securityPrincipal.PropagateToClientContext(ctx, encodedPrincipal, m.PropagationType)

			// 4. Call the next handler in the chain with the new context.
			return handler(newCtx, req)
		}
	}
}
