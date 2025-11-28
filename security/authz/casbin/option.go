/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	"github.com/origadmin/contrib/security/authz/casbin/adapter"
	"github.com/origadmin/contrib/security/authz/casbin/internal/model"
	"github.com/origadmin/contrib/security/authz/casbin/internal/policy"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

// Options holds configuration for the Casbin Authorizer, used with optionutil.
type Options struct {
	Model        casbinmodel.Model
	Policy       persist.Adapter
	WildcardItem string
}

// Apply applies the configurations from this Options struct to an Authorizer instance.
func (o *Options) Apply(s *Authorizer) error {
	if o.Policy != nil {
		s.policy = o.Policy
	} else {
		s.policy = adapter.NewMemory()
	}

	if o.Model != nil {
		s.model = o.Model
	} else {
		m, err := casbinmodel.NewModelFromString(DefaultModel()) // Default model
		if err != nil {
			return err
		}
		s.model = m
	}

	if o.WildcardItem != "" {
		s.wildcardItem = o.WildcardItem
	} else {
		s.wildcardItem = "*" // Default wildcard item
	}

	// Enforcer creation logic will be moved to NewAuthorizer
	return nil
}

// DefaultModel returns the default Casbin model string.
func DefaultModel() string {
	return model.DefaultRestfullWithRoleModel
}

// DefaultPolicy returns the default Casbin policy data. (Still unused, but kept for now as it was in original)
func DefaultPolicy() []byte {
	return policy.MustPolicy("keymatch_with_rbac_in_domain.csv")
}

// WithModel sets the Casbin model for the Authorizer.
func WithModel(m casbinmodel.Model) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Model = m
	})
}

// WithStringModel sets the Casbin model from a string.
// It panics if the model cannot be created from the string.
func WithStringModel(str string) options.Option {
	return optionutil.Update(func(o *Options) {
		m, err := casbinmodel.NewModelFromString(str)
		if err != nil {
			panic(err) // Fail fast during configuration if model string is invalid
		}
		o.Model = m
	})
}

// WithFileModel sets the Casbin model from a file path.
// It panics if the model cannot be created from the file.
func WithFileModel(path string) options.Option {
	return optionutil.Update(func(o *Options) {
		m, err := casbinmodel.NewModelFromFile(path)
		if err != nil {
			panic(err)
		}
		o.Model = m
	})
}

// WithNameModel sets the Casbin model by its predefined name.
// It panics if the named model cannot be found or created.
func WithNameModel(name string) options.Option {
	return optionutil.Update(func(o *Options) {
		m, err := casbinmodel.NewModelFromString(model.MustModel(name))
		if err != nil {
			panic(err) // Fail fast during configuration if named model is invalid
		}
		o.Model = m
	})
}

// WithPolicyAdapter sets the Casbin policy adapter.
func WithPolicyAdapter(p persist.Adapter) options.Option {
	return optionutil.Update(func(o *Options) {
		o.Policy = p
	})
}

// WithWildcardItem sets the wildcard item for domain matching.
func WithWildcardItem(item string) options.Option {
	return optionutil.Update(func(o *Options) {
		o.WildcardItem = item
	})
}

// FromOptions creates a new Options struct by applying the given options.
func FromOptions(opts []options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
