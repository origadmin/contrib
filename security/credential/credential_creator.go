/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package credential provides interfaces and implementations for credential management.
package credential

import (
	"context"

	"github.com/origadmin/contrib/security"
)

// CredentialCreator defines the contract for issuing new credentials.
type CredentialCreator interface {
	// CreateCredential issues a new credential for the given principal and returns
	// a standard, serializable Credential.
	CreateCredential(ctx context.Context, p security.Principal) (security.CredentialResponse, error)
}
