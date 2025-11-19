package principal

import (
	"encoding/base64"
	"fmt"

	"google.golang.org/protobuf/proto"

	securityifaces "github.com/origadmin/contrib/security" // Updated import path
	securityv1 "github.com/origadmin/contrib/security/api/gen/go/config/v1"
	"github.com/origadmin/runtime/context"
)

const (
	// MetadataKey is the key used to store the Principal in gRPC metadata or HTTP headers.
	MetadataKey = "x-principal-proto"
)

type principalKey struct{}

// FromContext extracts the Principal from the given context.
// It returns the Principal and a boolean indicating if it was found.
func FromContext(ctx context.Context) (securityifaces.Principal, bool) { // Use securityifaces.Principal
	p, ok := ctx.Value(principalKey{}).(securityifaces.Principal)
	return p, ok
}

// WithContext returns a new context with the given Principal attached.
// It is used to inject the Principal into the context for downstream business logic.
func WithContext(ctx context.Context, p securityifaces.Principal) context.Context { // Use securityifaces.Principal
	return context.WithValue(ctx, principalKey{}, p)
}

// EncodePrincipal encodes a security.Principal into a base64-encoded Protobuf string.
func EncodePrincipal(p securityifaces.Principal) (string, error) { // Use securityifaces.Principal
	if p == nil {
		return "", nil
	}
	data, err := proto.Marshal(p.Export())
	if err != nil {
		return "", fmt.Errorf("failed to marshal proto.Principal: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodePrincipal decodes a base64-encoded Protobuf string into a security.Principal.
func DecodePrincipal(encoded string) (securityifaces.Principal, error) { // Use securityifaces.Principal
	if encoded == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 string: %w", err)
	}
	protoP := &securityv1.Principal{}
	if err := proto.Unmarshal(data, protoP); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proto.Principal: %w", err)
	}
	return FromProto(protoP)
}
