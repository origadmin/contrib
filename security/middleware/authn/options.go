// Package authn implements the functions, types, and interfaces for the module.
package authn

import (
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

type Options struct {
	Authenticator   authn.Authenticator
	SkipChecker     SkipChecker
	PropagationType principal.PropagationType // Added field
}

func WithAuthenticator(authenticator authn.Authenticator) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Authenticator = authenticator
	})
}

func WithSkipChecker(skipChecker SkipChecker) options.Option {
	return optionutil.Update(func(o *Options) {
		o.SkipChecker = skipChecker
	})
}

// WithPropagationType sets the propagation type for the middleware.
func WithPropagationType(pt principal.PropagationType) options.Option {
	return optionutil.Update(func(o *Options) {
		o.PropagationType = pt
	})
}

func FromOptions(opts []options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
