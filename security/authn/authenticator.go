/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package authn provides interfaces and implementations for authentication.
package authn

import (
	"context"

	"github.com/origadmin/contrib/security"
)

// Authenticator is responsible for validating the identity of the request initiator.
// It receives credential data and returns a Principal object.
type Authenticator interface {
	// Authenticate validates the provided credential and returns a Principal object if successful.
	Authenticate(ctx context.Context, cred security.Credential) (security.Principal, error)

	// Supports returns true if this authenticator can handle the given credential.
	// For example, a JWTAuthenticator would return true for a credential where cred.Type() == "jwt".
	Supports(cred security.Credential) bool
}
