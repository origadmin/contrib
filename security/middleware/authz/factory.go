/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authz

import (
	"fmt"

	kratosMiddleware "github.com/go-kratos/kratos/v2/middleware"

	authzv1 "github.com/origadmin/contrib/security/api/gen/go/config/authz/v1"
	runtimeMiddleware "github.com/origadmin/runtime/middleware"
	"github.com/origadmin/runtime/interfaces/options"

	authzFactory "github.com/origadmin/contrib/security/authz"
)

// authzMiddlewareFactory implements the runtime/middleware.Factory interface for authorization middleware.
type authzMiddlewareFactory struct {
	provider authzFactory.Provider
}

// NewMiddlewareClient creates a new client-side authorization middleware.
func (f *authzMiddlewareFactory) NewMiddlewareClient(cfg *authzv1.Authorizer, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	// Client-side authorization is less common and typically not needed for simple propagation.
	// If needed, it would involve propagating authorization context.
	return nil, false
}

// NewMiddlewareServer creates a new server-side authorization middleware.
func (f *authzMiddlewareFactory) NewMiddlewareServer(cfg *authzv1.Authorizer, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	return NewAuthZMiddleware(f.provider, opts...).Server(), true
}

func init() {
	// Similar to authn, this registration needs to happen from the top-level application builder,
	// where the authzFactory.Provider is available.
	//
	// The correct way is for the application's main builder to:
	// 1. Create the authzFactory.Provider instances.
	// 2. Create an instance of authzMiddlewareFactory, injecting the provider.
	// 3. Register that specific authzMiddlewareFactory instance with runtimeMiddleware.Register.
	//
	// For now, we'll leave this as a conceptual placeholder and assume the application builder
	// handles the registration with the correct provider injection.
	//
	// runtimeMiddleware.Register(runtimeMiddleware.AuthZ, &authzMiddlewareFactory{})
}

// RegisterAuthZMiddlewareFactory is a helper function for the application builder to register
// the authorization middleware factory with the necessary provider.
func RegisterAuthZMiddlewareFactory(provider authzFactory.Provider) {
	runtimeMiddleware.Register(runtimeMiddleware.AuthZ, &authzMiddlewareFactory{provider: provider})
}
