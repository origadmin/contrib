/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authz

import (
	authzv1 "github.com/origadmin/contrib/api/gen/go/config/security/authz/v1"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/contrib/security" // Import the security package for Authorizer
)

// Provider is an interface for a security component that can provide authorization capabilities.
type Provider interface {
	// Authorizer returns the Authorizer capability, if supported.
	Authorizer() (security.Authorizer, bool) // Use security.Authorizer
}

// Factory is a function type that creates a Provider instance.
type Factory func(config *authzv1.Authorizer, opts ...options.Option) (Provider, error)
