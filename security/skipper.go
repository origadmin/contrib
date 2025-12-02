package security

import (
	"context"
)

// SkipChecker defines the function signature for determining whether to skip a middleware.
// It takes a context.Context and a Request, returning true if the middleware should be skipped.
type SkipChecker func(ctx context.Context, req Request) bool

// PathSkipChecker creates a SkipChecker that skips authentication for specified operation paths.
// The checker returns true if the request's operation matches any of the provided skipPaths.
func PathSkipChecker(skipPaths ...string) SkipChecker {
	skipSet := make(map[string]struct{}, len(skipPaths))
	for _, path := range skipPaths {
		skipSet[path] = struct{}{}
	}
	return func(ctx context.Context, req Request) bool {
		_, ok := skipSet[req.GetOperation()]
		return ok
	}
}

// NoOpSkipChecker creates a SkipChecker that never skips.
// This is the default behavior if no checker is provided, ensuring the middleware is always applied.
func NoOpSkipChecker() SkipChecker {
	return func(ctx context.Context, req Request) bool {
		return false
	}
}
