// Package authn implements the functions, types, and interfaces for the module.
package authn

import (
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

type Options struct {
	SkipChecker SkipChecker
}

func WithSkipChecker(skipChecker SkipChecker) options.Option {
	return optionutil.Update(func(o *Options) {
		o.SkipChecker = skipChecker
	})
}

func FromOptions(opts []options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
