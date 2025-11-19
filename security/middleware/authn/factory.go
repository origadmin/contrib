/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	"fmt"

	kratosMiddleware "github.com/go-kratos/kratos/v2/middleware"

	authnv1 "github.com/origadmin/contrib/api/gen/go/config/security/authn/v1"
	runtimeMiddleware "github.com/origadmin/runtime/middleware"
	"github.com/origadmin/runtime/interfaces/options"
	authnFactory "github.com/origadmin/contrib/security/authn"
)

// authnMiddlewareFactory implements the runtime/middleware.Factory interface for authentication middleware.
type authnMiddlewareFactory struct {
	provider authnFactory.Provider
}

// NewMiddlewareClient creates a new client-side authentication middleware.
func (f *authnMiddlewareFactory) NewMiddlewareClient(cfg *authnv1.Authenticator, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	// For client-side, we typically just need the AuthNMiddleware instance to propagate principal.
	return NewAuthNMiddleware(f.provider, opts...).Client(), true
}

// NewMiddlewareServer creates a new server-side authentication middleware.
func (f *authnMiddlewareFactory) NewMiddlewareServer(cfg *authnv1.Authenticator, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	return NewAuthNMiddleware(f.provider, opts...).Server(), true
}

func init() {
	// This init() block is problematic because it tries to register a factory that needs a provider,
	// but the provider is created much later in the application lifecycle.
	// The correct way is for the application's main builder to:
	// 1. Create the authnFactory.Provider instances.
	// 2. Create an instance of authnMiddlewareFactory, injecting the provider.
	// 3. Register that specific authnMiddlewareFactory instance with runtimeMiddleware.Register.
	//
	// For now, we'll leave this as a conceptual placeholder and assume the application builder
	// handles the registration with the correct provider injection.
	//
	// runtimeMiddleware.Register(runtimeMiddleware.AuthN, &authnMiddlewareFactory{})
}

// RegisterAuthNMiddlewareFactory is a helper function for the application builder to register
// the authentication middleware factory with the necessary provider.
func RegisterAuthNMiddlewareFactory(provider authnFactory.Provider) {
	runtimeMiddleware.Register(runtimeMiddleware.AuthN, &authnMiddlewareFactory{provider: provider})
}
