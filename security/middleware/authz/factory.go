// Package authz implements the functions, types, and interfaces for the module.
package authz

import (
	"errors"

	"github.com/origadmin/contrib/security/authz"
	middlewarev1 "github.com/origadmin/runtime/api/gen/go/config/middleware/v1"
	"github.com/origadmin/runtime/interfaces/options"
	runtimeMiddleware "github.com/origadmin/runtime/middleware"
)

const (
	MiddlewareName = "authz"
)

func init() {
	runtimeMiddleware.RegisterFactory(MiddlewareName, &factory{})
}

// factory implements the runtime/middleware.Factory interface for authorization middleware.
// It is responsible for creating authorization middleware instances.
// It relies on an external authz.Authorizer to handle the actual authorization logic.
type factory struct {
	authorizer authz.Authorizer
}

// NewFactory creates a new authorization middleware factory.
// The authorizer is injected to decouple the factory from the specific authorization mechanism.
func NewFactory(authorizer authz.Authorizer) (runtimeMiddleware.Factory, error) {
	if authorizer == nil {
		return nil, errors.New("authz authorizer cannot be nil")
	}
	return &factory{authorizer: authorizer}, nil
}

// NewMiddlewareClient creates a new client-side authorization middleware.
func (f *factory) NewMiddlewareClient(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() || cfg.GetName() != MiddlewareName {
		return nil, false
	}
	o := FromOptions(opts)
	authorizer := f.authorizer
	if o.Authorizer != nil {
		authorizer = o.Authorizer
	}
	return NewAuthZMiddleware(authorizer, opts...).Client(), true
}

// NewMiddlewareServer creates a new server-side authorization middleware.
func (f *factory) NewMiddlewareServer(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() || cfg.GetName() != MiddlewareName {
		return nil, false
	}
	o := FromOptions(opts)
	authorizer := f.authorizer
	if o.Authorizer != nil {
		authorizer = o.Authorizer
	}
	return NewAuthZMiddleware(authorizer, opts...).Server(), true
}

// Ensure factory implements the factory interface at compile time.
var _ runtimeMiddleware.Factory = (*factory)(nil)
