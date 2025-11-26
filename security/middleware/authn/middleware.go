/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

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
type Middleware struct {
	Authenticator authn.Authenticator
	SkipChecker   func(security.Request) bool
}

// NewAuthNMiddleware creates a new authentication middleware with required skip checker.
// The skipChecker function determines whether authentication should be skipped for a given request.
func NewAuthNMiddleware(n authn.Authenticator, opts ...options.Option) *Middleware {
	o := FromOptions(opts)
	// The 'opts' parameter is kept for future extensibility or other generic options,
	// but it's no longer needed for passing security configuration.
	a := &Middleware{
		Authenticator: n,
		SkipChecker:   o.SkipChecker,
	}
	if a.SkipChecker == nil {
		a.SkipChecker = NoOpSkipChecker()
	}
	return a
}

// SkipChecker is a function type for determining whether to skip authentication.
type SkipChecker func(security.Request) bool

// PathSkipChecker creates a skip checker that skips authentication for specified paths.
func PathSkipChecker(skipPaths map[string]bool) SkipChecker {
	return func(req security.Request) bool {
		if skipPaths == nil {
			return false
		}
		operation := req.GetOperation()
		return skipPaths[operation]
	}
}

// NoOpSkipChecker creates a skip checker that never skips authentication.
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
			// 1. Check if Principal already exists in context (e.g., from a previous middleware or test)
			if _, ok := securityPrincipal.FromContext(ctx); ok {
				return handler(ctx, req) // Already authenticated, proceed
			}
			securityReq, err := request.NewFromServerContext(ctx)
			if err != nil {
				return nil, err
			}
			if m.SkipChecker(securityReq) {
				return handler(ctx, req)
			}

			// 2. Extract credential from transport context
			var cred security.Credential
			if tr, ok := transport.FromServerContext(ctx); ok {
				// Assuming securityCredential.ExtractFromTransport can handle various transport types
				// and return a security.Credential object.
				cred, err = securityCredential.ExtractFromTransport(tr)
				if err != nil {
					// Log the error but don't necessarily return it as an API error yet,
					// as some endpoints might be public.
					// The Authenticate call below will return the appropriate API error.
					cred = securityCredential.NewEmptyCredential()
				}
			} else {
				// No transport context, create an empty credential
				cred = securityCredential.NewEmptyCredential()
			}

			// 3. Authenticate the credential
			principal, authErr := m.Authenticator.Authenticate(ctx, cred)
			if authErr != nil {
				// Authentication failed, return the specific API error
				return nil, authErr
			}

			// 4. Inject Principal into context
			ctx = securityPrincipal.NewContext(ctx, principal)

			return handler(ctx, req)
		}
	}
}

// Client implements the Kratos middleware (optional, for client-side authentication propagation)
func (m *Middleware) Client() middleware.KMiddleware {
	return func(handler middleware.KHandler) middleware.KHandler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			// Example: Propagate Principal from context to client request metadata
			if p, ok := securityPrincipal.FromContext(ctx); ok {
				if tr, ok := transport.FromClientContext(ctx); ok {
					encodedPrincipal, encodeErr := securityPrincipal.EncodePrincipal(p)
					if encodeErr != nil {
						return nil, encodeErr
					}
					tr.RequestHeader().Set(securityPrincipal.MetadataKey, encodedPrincipal)
				}
			}
			return handler(ctx, req)
		}
	}
}
