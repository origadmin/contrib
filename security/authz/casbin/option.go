/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package casbin

import (
	"github.com/casbin/casbin/v2/persist"

	casbinv1 "github.com/origadmin/contrib/api/gen/go/security/authz/casbin/v1"
	"github.com/origadmin/runtime/extension/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

const (
	// DefaultModel is the default Casbin model definition.
	// It defines a standard RBAC with domains model.
	DefaultModel = `
[request_definition]
r = sub, obj, act, dom

[policy_definition]
p = sub, obj, act, dom

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`
	defaultWildcardItem = "*"
)

// Options holds the configuration for the Casbin authorizer.
type Options struct {
	model        string
	adapter      persist.Adapter
	watcher      persist.Watcher
	wildcardItem string
}

// Apply applies the given configuration to the options.
func (o *Options) Apply(cfg *casbinv1.Config) error {
	if cfg == nil {
		return nil
	}

	if cfg.Model != "" {
		o.model = cfg.Model
	}
	if cfg.PolicyAdapter != nil {
		// Here you would have logic to create a policy adapter from the config.
		// For example, if cfg.PolicyAdapter.GetFile() is set, create a file adapter.
		// This part is highly dependent on the adapter implementations you support.
		// For now, we'll assume it's configured programmatically via WithAdapter.
	}

	return nil
}

// WithModel sets the Casbin model from a string.
func WithModel(model string) options.Option {
	return optionutil.Update(func(o *Options) {
		o.model = model
	})
}

// WithAdapter sets the policy adapter.
func WithAdapter(adapter persist.Adapter) options.Option {
	return optionutil.Update(func(o *Options) {
		o.adapter = adapter
	})
}

// WithWatcher sets the policy watcher for distributed systems.
func WithWatcher(watcher persist.Watcher) options.Option {
	return optionutil.Update(func(o *Options) {
		o.watcher = watcher
	})
}

// WithWildcardItem sets the wildcard item used in the model.
func WithWildcardItem(item string) options.Option {
	return optionutil.Update(func(o *Options) {
		o.wildcardItem = item
	})
}

// FromOptions creates a new Options struct from a slice of option functions.
func FromOptions(opts ...options.Option) *Options {
	o := &Options{
		model:        DefaultModel,
		adapter:      NewMemoryAdapter(), // Default to an in-memory adapter
		wildcardItem: defaultWildcardItem,
	}
	optionutil.ApplyOptions(o, opts...)
	return o
}
