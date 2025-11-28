package principal

import (
	"encoding/base64"
	"fmt"

	"google.golang.org/protobuf/proto"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	securityifaces "github.com/origadmin/contrib/security" // Updated import path
)

const (
	// MetadataKey is the key used to store the Principal in gRPC metadata or HTTP headers.
	MetadataKey = "x-md-global-principal-proto"
)

// EncodePrincipal encodes a securityifaces.Principal into a base64-encoded Protobuf string.
func EncodePrincipal(p securityifaces.Principal) (string, error) {
	if p == nil {
		return "", nil
	}
	data, err := proto.Marshal(p.Export())
	if err != nil {
		return "", fmt.Errorf("failed to marshal proto.Principal: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// DecodePrincipal decodes a base64-encoded Protobuf string into a securityifaces.Principal.
func DecodePrincipal(encoded string) (securityifaces.Principal, error) {
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
	// FromProto is in the same package (principal), so no need for explicit package qualifier
	return FromProto(protoP)
}
