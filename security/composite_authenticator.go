/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package security

import (
	"context"

	"github.com/go-kratos/kratos/v2/errors"
)

// CompositeAuthenticator is an authenticator that delegates to a list of other authenticators.
// It tries each authenticator in order until one of them successfully authenticates the credential.
type CompositeAuthenticator struct {
	authenticators []Authenticator
}

// NewCompositeAuthenticator creates a new CompositeAuthenticator.
// It takes a variadic list of authenticators to be tried in order.
func NewCompositeAuthenticator(authenticators ...Authenticator) Authenticator {
	return &CompositeAuthenticator{authenticators: authenticators}
}

// Authenticate iterates through the list of authenticators and calls the first one that supports the credential.
// If no authenticator supports the credential, it returns an "authenticator not found" error.
func (c *CompositeAuthenticator) Authenticate(ctx context.Context, cred Credential) (Principal, error) {
	for _, auth := range c.authenticators {
		if auth.Supports(cred) {
			return auth.Authenticate(ctx, cred)
		}
	}
	return nil, errors.Unauthorized("AUTHENTICATOR_NOT_FOUND", "no authenticator found for credential type: "+cred.Type())
}

// Supports returns true if any of the underlying authenticators supports the credential.
func (c *CompositeAuthenticator) Supports(cred Credential) bool {
	for _, auth := range c.authenticators {
		if auth.Supports(cred) {
			return true
		}
	}
	return false
}
