package security

// SkipChecker defines the function signature for determining whether to skip a middleware.
type SkipChecker func(req Request) bool

// PathSkipChecker creates a SkipChecker that skips authentication for specified operation paths.
func PathSkipChecker(skipPaths ...string) SkipChecker {
	skipSet := make(map[string]struct{}, len(skipPaths))
	for _, path := range skipPaths {
		skipSet[path] = struct{}{}
	}
	return func(req Request) bool {
		_, ok := skipSet[req.GetOperation()]
		return ok
	}
}

// NoOpSkipChecker creates a SkipChecker that never skips.
// This is the default behavior if no checker is provided.
func NoOpSkipChecker() SkipChecker {
	return func(req Request) bool {
		return false
	}
}
