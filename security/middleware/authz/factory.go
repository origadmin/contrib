/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authz

import (
	middlewarev1 "github.com/origadmin/runtime/api/gen/go/config/middleware/v1"
	"github.com/origadmin/runtime/interfaces/options"
	runtimeMiddleware "github.com/origadmin/runtime/middleware"

	"github.com/origadmin/contrib/security/authz"
)

const (
	MiddlewareName = "authz"
)

// factory implements the runtime/middleware.Factory interface for authorization middleware.
type factory struct {
	provider authz.Authorizer
}

// NewMiddlewareClient creates a new client-side authorization middleware.
func (f *factory) NewMiddlewareClient(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	// Client-side authorization is less common and typically not needed for simple propagation.
	// If needed, it would involve propagating authorization context.
	return nil, false
}

// NewMiddlewareServer creates a new server-side authorization middleware.
func (f *factory) NewMiddlewareServer(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() && cfg.GetName() != MiddlewareName {
		return nil, false
	}
	return NewAuthZMiddleware(f.provider, opts...).Server(), true
}

func init() {
	// Similar to authn, this registration needs to happen from the top-level application builder,
	// where the authz.Provider is available.
	//
	// The correct way is for the application's main builder to:
	// 1. Create the authz.Provider instances.
	// 2. Create an instance of factory, injecting the provider.
	// 3. Register that specific factory instance with runtimeMiddleware.Register.
	//
	// For now, we'll leave this as a conceptual placeholder and assume the application builder
	// handles the registration with the correct provider injection.
	//
	//runtimeMiddleware.RegisterFactory(MiddlewareName, &factory{})
}

// RegisterAuthZMiddlewareFactory is a helper function for the application builder to register
// the authorization middleware factory with the necessary provider.
func RegisterAuthZMiddlewareFactory(provider authz.Authorizer) {
	runtimeMiddleware.RegisterFactory(MiddlewareName, &factory{provider: provider})
}
