package security

import (
	"context"

	"google.golang.org/protobuf/types/known/structpb"

	configv1 "github.com/origadmin/contrib/security/api/gen/go/config/v1"
)

// Principal represents the identity of the entity making a request.
// It typically contains information about the authenticated user or service.
type Principal interface {
	// GetID returns the unique identifier of the principal.
	GetID() string
	// GetRoles returns a slice of roles assigned to the principal.
	GetRoles() []string
	// GetPermissions returns a slice of permissions granted to the principal.
	GetPermissions() []string
	// GetScopes returns a map of scopes associated with the principal.
	GetScopes() map[string]bool
	// GetClaims returns the custom claims associated with the principal.
	GetClaims() Claims
	// Export converts the Principal to its Protobuf representation.
	Export() *configv1.Principal
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

type principalContextKey struct{}

// FromContext extracts a Principal from the context.
// It returns the Principal and a boolean indicating if it was found.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}

// NewContext creates a new context with the given Principal.
func NewContext(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}
