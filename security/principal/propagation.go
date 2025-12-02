package principal

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	securityifaces "github.com/origadmin/contrib/security"
)

const (
	// MetadataKey is the key used to store the Principal in gRPC metadata or HTTP headers.
	MetadataKey = "x-md-global-principal-proto"
)

// Encode encodes a securityifaces.Principal into a base64-encoded Protobuf string.
func Encode(p securityifaces.Principal) (string, error) {
	if p == nil {
		return "", nil
	}
	data, err := proto.Marshal(p.Export())
	if err != nil {
		return "", fmt.Errorf("failed to marshal proto.Principal: %w", err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// Decode decodes a base64-encoded Protobuf string into a securityifaces.Principal.
func Decode(encoded string) (securityifaces.Principal, error) {
	if encoded == "" {
		return nil, nil // Return nil principal if empty, not an error
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

// Inject injects an encoded principal string into an outgoing request context.
// It prioritizes the Kratos transport abstraction but falls back to the native gRPC metadata mechanism.
func Inject(ctx context.Context, encodedPrincipal string) context.Context {
	// Prioritize Kratos transport, which handles both HTTP and gRPC.
	if tr, ok := transport.FromClientContext(ctx); ok {
		tr.RequestHeader().Set(MetadataKey, encodedPrincipal)
		return ctx // Kratos transporter header is modified in-place.
	}
	// Fallback for native gRPC contexts that don't have a Kratos transporter.
	return metadata.AppendToOutgoingContext(ctx, MetadataKey, encodedPrincipal)
}

// Extract extracts an encoded principal string from an incoming request context.
// It prioritizes the Kratos transport abstraction but falls back to the native gRPC metadata mechanism.
func Extract(ctx context.Context) (string, bool) {
	// Prioritize Kratos transport, which handles both HTTP and gRPC.
	if tr, ok := transport.FromServerContext(ctx); ok {
		if encodedPrincipal := tr.RequestHeader().Get(MetadataKey); encodedPrincipal != "" {
			return encodedPrincipal, true
		}
	} else if md, ok := metadata.FromIncomingContext(ctx); ok { // Fallback for native gRPC.
		if vals := md.Get(MetadataKey); len(vals) > 0 {
			return vals[0], true
		}
	}
	return "", false
}