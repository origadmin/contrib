// Package noop implements the functions, types, and interfaces for the module.
package noop

import (
	authnv1 "github.com/origadmin/runtime/api/gen/go/config/security/authn/v1"
	"github.com/origadmin/runtime/context"
	"github.com/origadmin/runtime/extension/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/interfaces/security"
	"github.com/origadmin/runtime/security/authn"
)

func init() {
	authn.RegisterAuthenticatorFactory("noop", NewNoopAuthenticator)
}

type authenticator struct {
	o *Options
}

func (a authenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	//TODO implement me
	panic("implement me")
}

func (a authenticator) Supports(cred security.Credential) bool {
	//TODO implement me
	panic("implement me")
}

func NewNoopAuthenticator(authnConfig *authnv1.Authenticator, opts ...options.Option) (security.Authenticator, error) {
	o := FromOptions(opts)
	err := o.Apply(authnConfig)
	if err != nil {
		return nil, err
	}
	return &authenticator{
		o: o,
	}, nil
}

func FromOptions(opts []options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
