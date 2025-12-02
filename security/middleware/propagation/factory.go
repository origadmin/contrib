package propagation

import (
	middlewarev1 "github.com/origadmin/runtime/api/gen/go/config/middleware/v1"
	"github.com/origadmin/runtime/interfaces/options"
	runtimeMiddleware "github.com/origadmin/runtime/middleware"
)

const (
	MiddlewareName = "propagation"
)

func init() {
	runtimeMiddleware.RegisterFactory(MiddlewareName, &factory{})
}

// factory is a stateless factory for creating authorization middleware.
type factory struct{}

// NewMiddlewareClient creates a new client-side authorization middleware.
func (f *factory) NewMiddlewareClient(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() || cfg.GetName() != MiddlewareName {
		return nil, false
	}
	o := fromOptions(opts)
	return newMiddleware(o).Client(), true
}

// NewMiddlewareServer creates a new server-side authorization middleware.
func (f *factory) NewMiddlewareServer(cfg *middlewarev1.Middleware, opts ...options.Option) (runtimeMiddleware.KMiddleware, bool) {
	if !cfg.GetEnabled() || cfg.GetName() != MiddlewareName {
		return nil, false
	}
	o := fromOptions(opts)
	return newMiddleware(o).Server(), true
}
