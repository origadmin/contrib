/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	"context"

	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/authn"
	"github.com/origadmin/contrib/security/credential"
	"github.com/origadmin/runtime/interfaces/options"
)

// Provider is an interface for a security component that can provide various authentication-related capabilities.
type Provider interface {
	// Authenticator returns the Authenticator capability, if supported.
	Authenticator() (authn.Authenticator, bool)
	// CredentialCreator returns the CredentialCreator capability, if supported.
	CredentialCreator() (credential.Creator, bool)
	// CredentialRevoker returns the CredentialRevoker capability, if supported.
	CredentialRevoker() (credential.Revoker, bool)
}

// Factory is a function type that creates a Provider instance.
type Factory func(config *authnv1.Authenticator, opts ...options.Option) (Provider, error)
