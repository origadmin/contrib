// Package noop implements the functions, types, and interfaces for the module.
package noop

import (
	"context"

	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/credential"
	"github.com/origadmin/contrib/security/principal"
	"github.com/origadmin/runtime/interfaces/options"
)

func init() {
	authn.Register("noop", &NoopFactory{})
}

type authenticator struct{}

func (a authenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	return principal.EmptyPrincipal(""), nil
}

func (a authenticator) Supports(cred security.Credential) bool {
	//TODO implement me
	panic("implement me")
}

type NoopFactory struct{}

func (f *NoopFactory) NewAuthenticator(cfg *authnv1.Authenticator, opts ...options.Option) (authn.Provider, error) {
	o := FromOptions(opts...)
	err := o.Apply(cfg)
	if err != nil {
		return nil, err
	}
	return &noopProvider{
		auth: &authenticator{},
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
