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

// Request provides access to security-relevant information needed for authorization decisions.
// It abstracts away the underlying transport (HTTP/gRPC) and provides a unified interface
// for accessing request metadata, operation details, and routing information.
type Request interface {
	// Kind returns the type of the request as a string (e.g., "grpc", "http").
	// This helps consumers understand how to interpret GetOperation(), GetMethod(), and GetRouteTemplate().
	Kind() string

	// GetOperation returns the primary identifier for the logical operation being performed.
	// The specific value depends on the Kind() and the nature of the request:
	// - For "grpc" kind: Returns the full gRPC method name (e.g., /package.Service/Method).
	// - For "http" kind:
	//   - If the HTTP request is a proxy for a gRPC method (e.g., via Kratos HTTP gateway),
	//     it returns the corresponding full gRPC method name.
	//   - Otherwise (for a pure HTTP service request), it returns the actual HTTP request path (e.g., /v1/users/123).
	// This value is typically used for policy lookup in `servicePolicies` (if it's a gRPC method name)
	// or for general operation identification.
	GetOperation() string

	// GetMethod returns the HTTP verb (e.g., "GET", "POST") if the request is an HTTP call.
	// For "grpc" kind requests, this method will return an empty string.
	GetMethod() string

	// GetRouteTemplate returns the matched HTTP route template (e.g., "/v1/users/{id}")
	// if the request is an HTTP call and a route template was matched.
	// This is typically used for policy lookup in `gatewayPolicies`.
	// For "grpc" kind requests, this method will return an empty string.
	GetRouteTemplate() string

	// Get returns the first value associated with the given key.
	// If the key is not found, it returns an empty string.
	Get(key string) string
	// Values returns the values associated with the given key.
	// It returns a slice of strings because sources like HTTP headers can have
	// multiple values for the same key.
	Values(key string) []string
	// GetAll returns all key-value pairs from the source.
	GetAll() map[string][]string
}
