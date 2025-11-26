/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	"fmt"

	"github.com/origadmin/contrib/security/authn"
	middlewarev1 "github.com/origadmin/runtime/api/gen/go/config/middleware/v1"
	"github.com/origadmin/runtime/interfaces/options"
	runtimeMiddleware "github.com/origadmin/runtime/middleware"
)

// Factory implements the runtime/middleware.Factory interface for authentication middleware.
// It is responsible for creating authentication middleware instances.
// It relies on an external authn.Provider to handle the actual authentication logic.
type Factory struct {
	provider authn.Provider
}

// NewFactory creates a new middleware factory.
// The provider is injected to decouple the factory from the specific authentication mechanism.
func NewFactory(mgr *authn.Manager) (runtimeMiddleware.Factory, error) {
	if mgr == nil {
		return nil, fmt.Errorf("authn manager cannot be nil")
	}
	provider, ok := mgr.GetProvider()
	if !ok {
		return nil, fmt.Errorf("authn provider not configured in manager")
	}
	return &Factory{provider: provider}, nil
}

// NewMiddlewareClient creates a new client-side authentication middleware.
func (f *Factory) NewMiddlewareClient(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	// Check if the middleware is explicitly disabled in the generic middleware configuration.
	// Assuming 'middlewarev1.Middleware' has an 'Enabled' field, potentially a *wrapperspb.BoolValue.
	if cfg != nil && cfg.GetEnabled() != nil && !cfg.GetEnabled().GetValue() {
		return nil, false // Middleware is disabled
	}
	// For client-side, we typically just need the AuthNMiddleware instance to propagate principal.
	// Use NoOpSkipChecker for client-side as authentication is typically handled on server
	return NewAuthNMiddleware(f.provider, NoOpSkipChecker(), opts...).Client(), true
}

// NewMiddlewareServer creates a new server-side authentication middleware.
func (f *Factory) NewMiddlewareServer(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	// Check if the middleware is explicitly disabled in the generic middleware configuration.
	// Assuming 'middlewarev1.Middleware' has an 'Enabled' field, potentially a *wrapperspb.BoolValue.
	if cfg != nil && cfg.GetEnabled() != nil && !cfg.GetEnabled().GetValue() {
		return nil, false // Middleware is disabled
	}
	// For server-side, use NoOpSkipChecker by default. Skip logic should be configured by the user.
	return NewAuthNMiddleware(f.provider, NoOpSkipChecker(), opts...).Server(), true
}

// Ensure Factory implements the Factory interface at compile time.
var _ runtimeMiddleware.Factory = (*Factory)(nil)
