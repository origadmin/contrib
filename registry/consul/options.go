/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package consul

import (
	"github.com/go-kratos/kratos/contrib/registry/consul/v2"

	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

// optionsKey is a private key type to avoid collisions in context.
type optionsKey struct{}

// consulOptions holds specific options for the Consul options.
// Pointers are used to distinguish between a zero value and a value not being set.
type consulOptions struct {
	Options []consul.Option
}

func WithConsulOption(opts ...consul.Option) options.Option {
	return optionutil.Update(func(o *consulOptions) {
		o.Options = opts
	})
}

func fromOptions(opts []options.Option) *consulOptions {
	return optionutil.NewT[consulOptions](opts...)
}
