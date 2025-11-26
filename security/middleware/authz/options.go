// Package authz implements the functions, types, and interfaces for the module.
package authz

import (
	"github.com/origadmin/contrib/security/authz"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

// Options defines the configuration options for the authorization middleware.
type Options struct {
	Authorizer  authz.Authorizer
	SkipChecker SkipChecker
}

// WithAuthorizer creates an option to set the authorizer for the middleware.
func WithAuthorizer(authorizer authz.Authorizer) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Authorizer = authorizer
	})
}

// WithSkipChecker creates an option to set the skip checker for the middleware.
func WithSkipChecker(skipChecker SkipChecker) options.Option {
	return optionutil.Update(func(o *Options) {
		o.SkipChecker = skipChecker
	})
}

// FromOptions creates a new Options instance from a slice of options.
func FromOptions(opts []options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
