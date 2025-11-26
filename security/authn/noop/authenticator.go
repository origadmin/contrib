// Package noop implements the functions, types, and interfaces for the module.
package noop

import (
	"context"

	"github.com/origadmin/contrib/security"
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/runtime/extension/optionutil"
	"github.com/origadmin/contrib/security/credential"
	"github.com/origadmin/runtime/interfaces/options"
)

func init() {
	authn.Register("noop", &NoopFactory{})
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

type NoopFactory struct{}

func (f *NoopFactory) NewProvider(cfg *authnv1.Authenticator, opts ...options.Option) (authn.Provider, error) {
	o := FromOptions(opts...)
	err := o.Apply(cfg)
	if err != nil {
		return nil, err
	}
	return &noopProvider{
		auth: &authenticator{
			o: o,
		},
	}, nil
}

type noopProvider struct {
	auth *authenticator
}

func (p *noopProvider) Authenticator() (authn.Authenticator, bool) {
	return p.auth, true
}

func (p *noopProvider) CredentialCreator() (credential.Creator, bool) {
	return nil, false
}

func (p *noopProvider) CredentialRevoker() (credential.Revoker, bool) {
	return nil, false
}

func FromOptions(opts ...options.Option) *Options {
	return optionutil.NewT[Options](opts...)
}
