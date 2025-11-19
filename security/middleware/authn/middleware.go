/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"

	authnv1 "github.com/origadmin/contrib/security/api/gen/go/config/authn/v1"
	securityv1 "github.com/origadmin/contrib/security/api/gen/go/config/v1"
	"github.com/origadmin/runtime/interfaces/options"

	securityifaces "github.com/origadmin/contrib/security/security"
	authnFactory "github.com/origadmin/contrib/security/authn"
	securityPrincipal "github.com/origadmin/contrib/security/principal"
	securityCredential "github.com/origadmin/contrib/security/credential"
)

// AuthNMiddleware is a Kratos middleware for authentication.
type AuthNMiddleware struct {
	provider authnFactory.Provider
	opts     []options.Option
}

// NewAuthNMiddleware creates a new authentication middleware.
func NewAuthNMiddleware(provider authnFactory.Provider, opts ...options.Option) *AuthNMiddleware {
	return &AuthNMiddleware{
		provider: provider,
		opts:     opts,
	}
}

// Server implements the Kratos middleware.
func (m *AuthNMiddleware) Server() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			// 1. Check if Principal already exists in context (e.g., from a previous middleware or test)
			if _, ok := securityPrincipal.FromContext(ctx); ok {
				return handler(ctx, req) // Already authenticated, proceed
			}

			// 2. Extract credential from transport context
			var cred securityifaces.Credential
			if tr, ok := transport.FromServerContext(ctx); ok {
				// Assuming securityCredential.ExtractFromTransport can handle various transport types
				// and return a security.Credential object.
				cred, err = securityCredential.ExtractFromTransport(tr)
				if err != nil {
					// Log the error but don't necessarily return it as an API error yet,
					// as some endpoints might be public.
					// The Authenticate call below will return the appropriate API error.
					cred = securityCredential.NewEmptyCredential() // Provide an empty credential to Authenticate
				}
			} else {
				// No transport context, create an empty credential
				cred = securityCredential.NewEmptyCredential()
			}

			// 3. Authenticate the credential
			authenticator, ok := m.provider.Authenticator()
			if !ok {
				return nil, securityv1.ErrorSigningMethodUnsupported("authentication provider does not support Authenticator interface")
			}

			principal, authErr := authenticator.Authenticate(ctx, cred)
			if authErr != nil {
				// Authentication failed, return the specific API error
				return nil, authErr
			}

			// 4. Inject Principal into context
			ctx = securityPrincipal.WithContext(ctx, principal)

			return handler(ctx, req)
		}
	}
}

// Client implements the Kratos middleware (optional, for client-side authentication propagation)
func (m *AuthNMiddleware) Client() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
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
