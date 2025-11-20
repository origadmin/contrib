/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	"github.com/origadmin/runtime/interfaces/options"
	securityifaces "github.com/origadmin/contrib/security/security" // Updated import path
)

// Provider is an interface for a security component that can provide various authentication-related capabilities.
type Provider interface {
	// Authenticator returns the Authenticator capability, if supported.
	Authenticator() (securityifaces.Authenticator, bool) // Use securityifaces.Authenticator
	// CredentialCreator returns the CredentialCreator capability, if supported.
	CredentialCreator() (securityifaces.CredentialCreator, bool) // Use securityifaces.CredentialCreator
	// CredentialRevoker returns the CredentialRevoker capability, if supported.
	CredentialRevoker() (securityifaces.CredentialRevoker, bool) // Use securityifaces.CredentialRevoker
}

// Factory is a function type that creates a Provider instance.
type Factory func(config *authnv1.Authenticator, opts ...options.Option) (Provider, error)
