/* * Copyright (c) 2024 OrigAdmin. All rights reserved. */

package jwt

import (
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	authnFactory "github.com/origadmin/contrib/security/authn"
	securityCredential "github.com/origadmin/contrib/security/credential"
)

// provider implements the authn.Provider interface for the JWT component.
// It holds the central authenticator instance and the security configuration
// to determine skip logic.
type provider struct {
	auth *Authenticator
}

// newProvider creates a new JWT provider.
func newProvider(auth *Authenticator, cfg *authnv1.Authenticator) *provider {
	p := &provider{
		auth: auth,
	}

	// TODO: Add skip_paths configuration when available in protobuf
	// Pre-process skip_paths from the configuration for efficient lookup
	// if cfg != nil && cfg.GetJwt() != nil {
	//	for _, path := range cfg.GetJwt().GetSkipPaths() {
	//		p.skipPaths[path] = true
	//	}
	// }
	return p
}

// Authenticator returns the Authenticator capability.
func (p *provider) Authenticator() (authnFactory.Authenticator, bool) {
	return p.auth, true
}

// CredentialCreator returns the CredentialCreator capability.
func (p *provider) CredentialCreator() (securityCredential.Creator, bool) {
	// The JWT Authenticator struct implements Creator.
	return p.auth, true
}

// CredentialRevoker returns the CredentialRevoker capability.
func (p *provider) CredentialRevoker() (securityCredential.Revoker, bool) {
	// The JWT Authenticator struct implements Revoker.
	return p.auth, true
}
