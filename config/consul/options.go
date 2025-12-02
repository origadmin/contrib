// Package consul implements the functions, types, and interfaces for the module.
package consul

import (
	"github.com/go-kratos/kratos/contrib/config/consul/v2"

	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

type Options struct {
	Options []consul.Option
}

func WithConsulOption(opts ...consul.Option) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Options = opts
	})
}

func FromOptions(opts []options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
