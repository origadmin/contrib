/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package jwt

import (
	"strings"

	authnFactory "github.com/origadmin/contrib/security/authn" // Updated import path
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	securityifaces "github.com/origadmin/contrib/security/security" // Updated import path
)

// provider implements the authn.Provider interface for the JWT component.
// It holds the central authenticator instance and the security configuration
// to determine skip logic.
type provider struct {
	auth      *Authenticator
	skipPaths map[string]bool // Pre-processed skip paths for quick lookup
}

// newProvider creates a new JWT provider.
func newProvider(auth *Authenticator, cfg *securityv1.Security) authnFactory.Provider { // Use authnFactory.Provider
	p := &provider{
		auth:      auth,
		skipPaths: make(map[string]bool),
	}

	// Pre-process skip_paths from the configuration for efficient lookup
	if cfg != nil && cfg.GetAuthn() != nil {
		for _, path := range cfg.GetAuthn().GetSkipPaths() {
			p.skipPaths[path] = true
		}
	}
	return p
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

// ShouldSkip implements the authn.Provider interface.
// It checks if a given operation (e.g., gRPC method or HTTP path) should bypass authentication.
func (p *provider) ShouldSkip(operation string) bool {
	if p.skipPaths == nil {
		return false
	}
	// Direct check first for exact matches
	if p.skipPaths[operation] {
		return true
	}
	return false
}
