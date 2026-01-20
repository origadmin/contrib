/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	casbinmodel "github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"

	"github.com/origadmin/contrib/security/authz/casbin/internal/model"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/log"
)

// Options holds configuration for the Casbin Authorizer, used with optionutil.
// All fields are unexported to enforce configuration via functional options,
// ensuring a controlled and validated setup process.
type Options struct {
	model        casbinmodel.Model
	policy       persist.Adapter
	watcher      persist.Watcher
	wildcardItem string
	Logger       log.Logger
}

type Option = options.Option

// DefaultModel returns the default Casbin model string.
func DefaultModel() string {
	return model.DefaultRestfullWithRoleModel
}

// WithModel sets the Casbin model for the Authorizer.
func WithModel(m casbinmodel.Model) Option {
	return optionutil.Update(func(o *Options) {
		o.model = m
	})
}

// WithStringModel sets the Casbin model from a string.
// It panics if the model cannot be created from the string.
func WithStringModel(str string) Option {
	return optionutil.Update(func(o *Options) {
		m, err := casbinmodel.NewModelFromString(str)
		if err != nil {
			panic(err) // Fail fast during configuration if model string is invalid
		}
		o.model = m
	})
}

// WithFileModel sets the Casbin model from a file path.
// It panics if the model cannot be created from the file.
func WithFileModel(path string) Option {
	return optionutil.Update(func(o *Options) {
		m, err := casbinmodel.NewModelFromFile(path)
		if err != nil {
			panic(err)
		}
		o.model = m
	})
}

// WithNameModel sets the Casbin model by its predefined name.
// It panics if the named model cannot be found or created.
func WithNameModel(name string) Option {
	return optionutil.Update(func(o *Options) {
		m, err := casbinmodel.NewModelFromString(model.MustModel(name))
		if err != nil {
			panic(err) // Fail fast during configuration if named model is invalid
		}
		o.model = m
	})
}

// WithPolicyAdapter sets the Casbin policy adapter.
func WithPolicyAdapter(p persist.Adapter) Option {
	return optionutil.Update(func(o *Options) {
		o.policy = p
	})
}

// WithWatcher sets the Casbin watcher for dynamic policy updates.
func WithWatcher(w persist.Watcher) Option {
	return optionutil.Update(func(o *Options) {
		o.watcher = w
	})
}

// WithWildcardItem sets the wildcard item for domain matching.
func WithWildcardItem(item string) Option {
	return optionutil.Update(func(o *Options) {
		o.wildcardItem = item
	})
}

// WithLogger sets the logger for the authorizer.
func WithLogger(logger log.Logger) Option {
	return log.WithLogger(logger)
}

// FromOptions creates a new Options struct by applying the given functional options.
func FromOptions(opts ...Option) *Options {
	o := &Options{}
	optionutil.Apply(o, opts...)

	// CORRECTED: Pass the slice directly without the variadic '...' operator.
	o.Logger = log.FromOptions(opts)

	return o
}
