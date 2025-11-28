package principal

import (
	"context"

	securityifaces "github.com/origadmin/contrib/security"
)

type principalContextKey struct{}
type domainContextKey struct{} // New type for domain context key

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

// DomainFromContext extracts a domain string from the context.
// It returns the domain string and a boolean indicating if it was found.
func DomainFromContext(ctx context.Context) (string, bool) {
	d, ok := ctx.Value(domainContextKey{}).(string)
	return d, ok
}

// NewDomainContext creates a new context with the given domain string.
func NewDomainContext(ctx context.Context, domain string) context.Context {
	return context.WithValue(ctx, domainContextKey{}, domain)
}
