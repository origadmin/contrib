/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	authnFactory "github.com/origadmin/contrib/security/authn"      // Updated import path
	securityifaces "github.com/origadmin/contrib/security/security" // Updated import path
)

// provider implements the authn.Provider interface for the JWT component.
// It holds the central authenticator instance which may implement multiple security interfaces.
type provider struct {
	auth *Authenticator
}

// newProvider creates a new JWT provider.
func newProvider(auth *Authenticator) authnFactory.Provider { // Use authnFactory.Provider
	return &provider{auth: auth}
}

// Authenticator returns the Authenticator capability.
func (p *provider) Authenticator() (securityifaces.Authenticator, bool) { // Use securityifaces.Authenticator
	return p.auth, true
}

// CredentialCreator returns the CredentialCreator capability.
func (p *provider) CredentialCreator() (securityifaces.CredentialCreator, bool) { // Use securityifaces.CredentialCreator
	// The JWT Authenticator struct implements CredentialCreator.
	return p.auth, true
}

// CredentialRevoker returns the CredentialRevoker capability.
func (p *provider) CredentialRevoker() (securityifaces.CredentialRevoker, bool) { // Use securityifaces.CredentialRevoker
	// The JWT Authenticator struct implements CredentialRevoker.
	return p.auth, true
}
