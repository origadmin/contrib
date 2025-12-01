package authn

import (
	middlewarev1 "github.com/origadmin/runtime/api/gen/go/config/middleware/v1"
	"github.com/origadmin/runtime/interfaces/options"
	runtimeMiddleware "github.com/origadmin/runtime/middleware"
)

const (
	MiddlewareName = "authn"
)

func init() {
	runtimeMiddleware.RegisterFactory("authn", &factory{})
}

// factory is a stateless factory for creating authentication middleware.
type factory struct{}

// NewMiddlewareClient creates a new client-side authentication middleware.
func (f *factory) NewMiddlewareClient(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() || cfg.GetName() != MiddlewareName {
		return nil, false
	}
	o := fromOptions(opts...)
	if o.Authenticator == nil {
		return nil, false
	}
	return newMiddleware(o).Client(), true
}

// NewMiddlewareServer creates a new server-side authentication middleware.
func (f *factory) NewMiddlewareServer(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() || cfg.GetName() != MiddlewareName {
		return nil, false
	}
	o := fromOptions(opts...)
	if o.Authenticator == nil {
		return nil, false
	}
	return newMiddleware(o).Server(), true
}
