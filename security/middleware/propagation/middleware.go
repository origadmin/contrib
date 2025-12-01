package propagation

import (
	"context"

	securityPrincipal "github.com/origadmin/contrib/security/principal"
	securityPrincipalProp "github.com/origadmin/contrib/security/principal" // Alias for propagation functions
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware"
)

// Middleware is a Kratos middleware for principal propagation.
// It embeds the Options struct to hold its configuration.
type Middleware struct {
	*Options
}

// New is a convenience function for creating a new principal propagation middleware.
func New(opts ...options.Option) *Middleware {
	o := fromOptions(opts...)
	return newMiddleware(o)
}

// newMiddleware is the internal constructor that takes a pre-parsed options struct.
func newMiddleware(opts *Options) *Middleware {
	return &Middleware{
		Options: opts,
	}
}

// Server implements the Kratos middleware for server-side principal extraction.
// It extracts an encoded principal from the incoming request, decodes it, and
// injects it into the context. This allows downstream middleware (like authz)
// to act on the propagated principal.
func (m *Middleware) Server() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			// If a principal already exists in the context (e.g., from a local authn middleware),
			// we do not overwrite it. The local principal takes precedence.
			if _, ok := securityPrincipal.FromContext(ctx); ok {
				return handler(ctx, req)
			}

			// Extract the encoded principal from the transport (gRPC metadata or HTTP header).
			encodedPrincipal := securityPrincipalProp.ExtractFromServerContext(m.PropagationType, ctx, req)
			if encodedPrincipal == "" {
				// No principal found in the request.
				return handler(ctx, req)
			}

			// Decode the principal.
			p, err := securityPrincipal.Decode(encodedPrincipal)
			if err != nil {
				// If decoding fails, it might be a malformed token.
				// We proceed without a principal, but could add logging here later.
				return handler(ctx, req)
			}

			// Inject the decoded principal into the context.
			newCtx := securityPrincipal.NewContext(ctx, p)
			return handler(newCtx, req)
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
			newCtx := securityPrincipalProp.PropagateToClientContext(m.PropagationType, ctx, req, encodedPrincipal)

			// 4. Call the next handler in the chain with the new context.
			return handler(newCtx, req)
		}
	}
}
