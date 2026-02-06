package security

import (
	"google.golang.org/protobuf/types/known/structpb"
)

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

// Claims represents a set of custom claims associated with a Principal.
// It provides methods for accessing and unmarshaling claim values.
type Claims interface {
	// Get retrieves a claim by its key and returns its value as an interface{}.
	// The second return value indicates if the claim was found.
	Get(key string) (any, bool)
	// GetString retrieves a string claim by its key.
	GetString(key string) (string, bool)
	// GetInt64 retrieves an int64 claim by its key.
	GetInt64(key string) (int64, bool)
	// GetFloat64 retrieves a float64 claim by its key.
	GetFloat64(key string) (float64, bool)
	// GetBool retrieves a boolean claim by its key.
	GetBool(key string) (bool, bool)
	// GetStringSlice retrieves a string slice claim by its key.
	GetStringSlice(key string) ([]string, bool)
	// GetMap retrieves a map[string]any claim by its key.
	GetMap(key string) (map[string]any, bool)
	// UnmarshalValue unmarshals a claim with the given key into the provided Go type.
	// The target must be a pointer to a struct.
	UnmarshalValue(key string, target any) error
	// Export returns the raw claims data as a map of structpb.Value.
	Export() map[string]*structpb.Value
}
