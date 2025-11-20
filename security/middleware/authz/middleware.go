/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authz

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"

	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	"github.com/origadmin/runtime/interfaces/options"

	authzFactory "github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/contrib/security" // Import the security package for Principal
)

// AuthZMiddleware is a Kratos middleware for authorization.
type AuthZMiddleware struct {
	provider authzFactory.Provider
	opts     []options.Option
	// TODO: Add configuration for resource mapping and action extraction
}

// NewAuthZMiddleware creates a new authorization middleware.
func NewAuthZMiddleware(provider authzFactory.Provider, opts ...options.Option) *AuthZMiddleware {
	return &AuthZMiddleware{
		provider: provider,
		opts:     opts,
	}
}

// Server implements the Kratos middleware.
func (m *AuthZMiddleware) Server() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			// 1. Get Principal from context
			p, ok := security.FromContext(ctx)
			if !ok {
				// If no principal, it means authentication failed or was skipped.
				// Depending on policy, this might be an unauthenticated access.
				// For now, we'll assume authorization requires authentication.
				return nil, securityv1.ErrorPermissionDenied("unauthenticated access")
			}

			// 2. Get Authorizer from provider
			authorizer, ok := m.provider.Authorizer()
			if !ok {
				return nil, securityv1.ErrorPermissionDenied("authorization provider does not support Authorizer interface")
			}

			// 3. Extract resource and action from request context
			// This part is highly dependent on the application's resource model.
			// For gRPC, it might be the full method name. For HTTP, it might be path + method.
			// For simplicity, let's assume we can get the full method name from transport context.
			var resource string
			var action string = "*" // Default action

			if tr, ok := transport.FromServerContext(ctx); ok {
				resource = tr.Operation() // For gRPC, Operation() returns full method name
				// For HTTP, we might need to parse tr.Request() to get path and method
			} else {
				return nil, securityv1.ErrorPermissionDenied("failed to get resource from transport context")
			}

			// 4. Perform authorization check
			authorized, authzErr := authorizer.Authorize(ctx, p, resource, action)
			if authzErr != nil {
				return nil, securityv1.ErrorPermissionDenied("authorization check failed: %v", authzErr)
			}
			if !authorized {
				return nil, securityv1.ErrorPermissionDenied("permission denied for resource %s, action %s", resource, action)
			}

			return handler(ctx, req)
		}
	}
}

// Client implements the Kratos middleware (optional, for client-side authorization propagation)
func (m *AuthZMiddleware) Client() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			// Client-side authorization is less common.
			// Could be used for propagating authorization decisions or context.
			return handler(ctx, req)
		}
	}
}
