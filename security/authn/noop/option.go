// Package noop implements the functions, types, and interfaces for the module.
package noop

import (
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

type Options struct {
}

func (o *Options) Apply(authn *authnv1.Authenticator) error {
	return nil
}

func FromOptions(opts ...options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
