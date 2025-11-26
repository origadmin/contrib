/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package cache provides token caching functionality for security module
package cache

import (
	"context"
	"time"
)

// Cache is the interface for caching the Authenticator token.
type Cache interface {
	// Store stores the token with a specific expiration time
	Store(context.Context, string, time.Duration) error
	// Exist checks if the token exists
	Exist(context.Context, string) (bool, error)
	// Remove deletes the token
	Remove(context.Context, string) error
	// Close closes the storage
	Close(context.Context) error
}
