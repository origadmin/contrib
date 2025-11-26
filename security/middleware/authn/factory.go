/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	"errors"

	"github.com/origadmin/contrib/security/authn"
	middlewarev1 "github.com/origadmin/runtime/api/gen/go/config/middleware/v1"
	"github.com/origadmin/runtime/interfaces/options"
	runtimeMiddleware "github.com/origadmin/runtime/middleware"
)

const (
	MiddlewareName = "authn"
)

// factory implements the runtime/middleware.Factory interface for authentication middleware.
// It is responsible for creating authentication middleware instances.
// It relies on an external authn.Provider to handle the actual authentication logic.
type factory struct {
	provider authn.Authenticator
}

// NewFactory creates a new middleware factory.
// The provider is injected to decouple the factory from the specific authentication mechanism.
func NewFactory(provider authn.Authenticator) (runtimeMiddleware.Factory, error) {
	if provider == nil {
		return nil, errors.New("authn manager cannot be nil")
	}
	//provider, ok := mgr.(authn.Authenticator)
	//if !ok {
	//	return nil, fmt.Errorf("authn provider not configured in manager")
	//}
	return &factory{provider: provider}, nil
}

// NewMiddlewareClient creates a new client-side authentication middleware.
func (f *factory) NewMiddlewareClient(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() && cfg.GetName() != MiddlewareName {
		return nil, false
	}
	return NewAuthNMiddleware(f.provider, opts...).Client(), true
}

// NewMiddlewareServer creates a new server-side authentication middleware.
func (f *factory) NewMiddlewareServer(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() && cfg.GetName() != MiddlewareName {
		return nil, false
	}
	return NewAuthNMiddleware(f.provider, opts...).Server(), true
}

// Ensure factory implements the factory interface at compile time.
var _ runtimeMiddleware.Factory = (*factory)(nil)
