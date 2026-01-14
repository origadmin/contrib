// Package skip implements the functions, types, and interfaces for the module.
package skip

import (
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/runtime/context"
)

// Path creates a Skipper that skips authentication for specified operation paths.
// The checker returns true if the request's operation matches any of the provided skipPaths.
func Path(paths ...string) security.Skipper {
	skipSet := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		skipSet[path] = struct{}{}
	}
	return func(ctx context.Context, req security.Request) bool {
		_, ok := skipSet[req.GetOperation()]
		return ok
	}
}

func Principal(fn func(principal security.Principal) bool) security.Skipper {
	return func(ctx context.Context, req security.Request) bool {
		if p, ok := security.FromContext(ctx); ok {
			return fn(p)
		}
		return false
	}
}

func ID(id string) security.Skipper {
	return func(ctx context.Context, req security.Request) bool {
		if p, ok := security.FromContext(ctx); ok {
			return p.GetID() == id
		}
		return false
	}
}

// Noop creates a Skipper that never skips.
// This is the default behavior if no checker is provided, ensuring the middleware is always applied.
func Noop() security.Skipper {
	return func(ctx context.Context, req security.Request) bool {
		return false
	}
}

// Composite returns a new skipper that chains multiple skippers.
// If any of the skippers returns true, the chain returns true.
func Composite(skippers ...security.Skipper) security.Skipper {
	return func(ctx context.Context, req security.Request) bool {
		for _, skipper := range skippers {
			if skipper(ctx, req) {
				return true
			}
		}
		return false
	}
}
