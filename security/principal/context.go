package principal

import (
	"context"

	securityifaces "github.com/origadmin/contrib/security"
)

type principalContextKey struct{}

// FromContext extracts a Principal from the context.
// It returns the Principal and a boolean indicating if it was found.
func FromContext(ctx context.Context) (securityifaces.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(securityifaces.Principal)
	return p, ok
}

// NewContext creates a new context with the given Principal.
func NewContext(ctx context.Context, p securityifaces.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}
