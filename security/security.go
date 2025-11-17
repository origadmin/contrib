package security

import (
	"sync"
)

// Policy holds all information for a single resource's policy.
// This struct is created by generated code and registered via init().
type Policy struct {
	ServiceMethod string // gRPC full method name, e.g., "/user.v1.UserService/GetUser"
	GatewayPath   string // HTTP path and method, e.g., "GET:/api/v1/users/{id}"
	Name          string // The policy name/definition string from the proto annotation, e.g., "admin-only"
	VersionID     string // A hash representing the version of this policy definition
}

// --- Global Policy Registry ---

var (
	// unifiedPolicies stores all policy registrations from generated code.
	// It's populated by init() functions via the RegisterPolicies function.
	unifiedPolicies []Policy

	mu sync.RWMutex
)

// RegisterPolicies is a public function called by generated code in init() functions.
// It appends a slice of policies to the global unifiedPolicies registry.
func RegisterPolicies(policies []Policy) {
	mu.Lock()
	defer mu.Unlock()
	unifiedPolicies = append(unifiedPolicies, policies...)
}

// RegisteredPolicies returns a copy of all policy registrations.
// This is called once at application startup to sync policies to the database.
func RegisteredPolicies() []Policy {
	mu.RLock()
	defer mu.RUnlock()

	clone := make([]Policy, len(unifiedPolicies))
	copy(clone, unifiedPolicies)
	return clone
}
