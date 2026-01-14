package security

import (
	"context"
)

type principalContextKey struct{}

// FromContext extracts a Principal from the context.
// It returns the Principal and a boolean indicating if it was found.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}

// NewContext creates a new context with the given Principal.
func NewContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}
