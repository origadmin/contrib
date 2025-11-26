/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package credential provides interfaces and implementations for credential management.
package credential

import (
	"context"

	"github.com/origadmin/contrib/security"
)

// Revoker is responsible for invalidating or revoking previously issued credentials.
// This is typically used for logout, forced sign-out, or security-related credential invalidation.
type Revoker interface {
	// Revoke invalidates the given credential, making it unusable for future authentication.
	// Implementations should parse the provided Credential object to extract the necessary
	// information (e.g., a token ID) to perform the revocation, for instance, by adding it
	// to a denylist.
	Revoke(ctx context.Context, cred security.Credential) error
}
