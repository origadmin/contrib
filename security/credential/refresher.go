/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package credential provides interfaces and implementations for credential management.
package credential

import (
	"context"

	"github.com/origadmin/contrib/security"
)

// Refresher defines the contract for refreshing credentials.
type Refresher interface {
	// RefreshCredential issues a new credential based on a valid refresh token.
	RefreshCredential(ctx context.Context, refreshToken string) (security.CredentialResponse, error)
}
