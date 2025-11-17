/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package security provides declarative security interfaces for authentication and authorization.
package security

import (
	"context"
)

// CredentialCreator defines the contract for issuing new credentials.
type CredentialCreator interface {
	// CreateCredential issues a new credential for the given principal and returns
	// a standard, serializable Credential.
	CreateCredential(ctx context.Context, p Principal) (CredentialResponse, error)
}
