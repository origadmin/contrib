package propagation

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/middleware"
)

// Middleware is a Kratos middleware for principal propagation.
type Middleware struct {
	*Options
	log *log.Helper
}

// New is a convenience function for creating a new principal propagation middleware.
func New(opts ...options.Option) *Middleware {
	o := fromOptions(opts)
	return newMiddleware(o)
}

// newMiddleware is the internal constructor that takes a pre-parsed options struct.
func newMiddleware(opts *Options) *Middleware {
	return &Middleware{
		Options: opts,
		log:     log.NewHelper(opts.Logger),
	}
}

// Server implements the Kratos middleware for server-side principal extraction.
func (m *Middleware) Server() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			if _, ok := securityPrincipal.FromContext(ctx); ok {
				// This is a normal case if another auth middleware ran first. No log needed.
				return handler(ctx, req)
			}

			encodedPrincipal := securityPrincipal.ExtractFromServerContext(m.PropagationType, ctx, req)
			if encodedPrincipal == "" {
				// This is also a normal case for unauthenticated requests. No log needed.
				return handler(ctx, req)
			}

			p, err := securityPrincipal.Decode(encodedPrincipal)
			if err != nil {
				m.log.WithContext(ctx).Warnf("[Propagation] Failed to decode principal from header: %v", err)
				return handler(ctx, req) // Proceed without principal on decode failure
			}

			newCtx := securityPrincipal.NewContext(ctx, p)
			m.log.WithContext(ctx).Debugf("[Propagation] Principal injected into context: ID=%s", p.GetID())
			return handler(newCtx, req)
		}
	}
}

// Client implements the Kratos middleware for client-side principal propagation.
func (m *Middleware) Client() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			p, ok := securityPrincipal.FromContext(ctx)
			if !ok {
				// Normal case, no principal to propagate.
				return handler(ctx, req)
			}

			encodedPrincipal, err := securityPrincipal.Encode(p)
			if err != nil {
				m.log.WithContext(ctx).Errorf("[Propagation] Failed to encode principal for propagation: %v", err)
				return nil, err // This is a critical internal error.
			}

			newCtx := securityPrincipal.PropagateToClientContext(m.PropagationType, ctx, req, encodedPrincipal)
			// This log is redundant as success is confirmed by the receiving service's log.
			// m.log.WithContext(ctx).Debugf("[Propagation] Propagating principal to client request: ID=%s", p.GetID())
			return handler(newCtx, req)
		}
	}
}
