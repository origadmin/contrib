/* * Copyright (c) 2024 OrigAdmin. All rights reserved. */

package casbin

import (
	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	"github.com/origadmin/contrib/security/authz/casbin/internal/model"
	"github.com/origadmin/contrib/security/authz/casbin/internal/policy"
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

type Options struct {
	model    casbinmodel.Model
	policy   persist.Adapter
	wildcard string
}

func DefaultModel() string {
	return model.DefaultRestfullWithRoleModel
}

func DefaultPolicy() []byte {
	return policy.MustPolicy("keymatch_with_rbac_in_domain.csv")
}

func WithModel(model casbinmodel.Model) options.Option {
	return optionutil.Update(func(s *Options) {
		s.model = model
	})
}

func WithStringModel(str string) options.Option {
	return optionutil.Update(func(s *Options) {
		s.model, _ = casbinmodel.NewModelFromString(str)
	})
}

func WithFileModel(path string) options.Option {
	return optionutil.Update(func(s *Options) {
		s.model, _ = casbinmodel.NewModelFromFile(path)
	})
}

func WithNameModel(name string) options.Option {
	return optionutil.Update(func(s *Options) {
		s.model, _ = casbinmodel.NewModelFromString(model.MustModel(name))
	})
}

func WithPolicyAdapter(policy persist.Adapter) options.Option {
	return optionutil.Update(func(s *Options) {
		s.policy = policy
	})
}

func FromOptions(opts []options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
