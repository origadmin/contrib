package security

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
