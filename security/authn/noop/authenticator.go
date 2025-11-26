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
	"github.com/origadmin/toolkits/errors"
)

func init() {
	authn.Register("noop", &noop{})
}

type authenticator struct{}

func (a authenticator) CreateCredential(ctx context.Context, p security.Principal) (security.CredentialResponse, error) {
	return nil, errors.New("noop authenticator does not support credential creation")

}

func (a authenticator) Revoke(ctx context.Context, cred security.Credential) error {
	return errors.New("noop authenticator does not support credential revocation")
}

func (a authenticator) Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error) {
	return principal.Anonymous(), nil
}

func (a authenticator) Supports(cred security.Credential) bool {
	return false
}

type noop struct{}

func (f *noop) NewAuthenticator(cfg *authnv1.Authenticator, opts ...options.Option) (authn.Authenticator, error) {
	//o := FromOptions(opts...)
	//err := o.Apply(cfg)
	//if err != nil {
	//	return nil, err
	//}
	return &authenticator{}, nil
}

// NewAuthenticator creates a new JWT Provider from the given configuration and options.
func NewAuthenticator(cfg *authnv1.Authenticator, opts ...options.Option) (authn.Authenticator, error) {
	return &authenticator{}, nil
}

var _ credential.Revoker = &authenticator{}
var _ credential.Creator = &authenticator{}
