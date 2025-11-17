// Package noop implements the functions, types, and interfaces for the module.
package noop

import (
	authnv1 "github.com/origadmin/runtime/api/gen/go/config/security/authn/v1"
)

type Options struct {
}

func (o *Options) Apply(authn *authnv1.Authenticator) error {
	return nil
}
