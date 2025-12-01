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
	// DomainMetadataKey is the key used to store the Domain in gRPC metadata or HTTP headers.
	DomainMetadataKey = "x-md-global-domain"
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

// Inject injects an already encoded principal string into the outgoing request context.
// It handles both HTTP and gRPC transports.
func Inject(ctx context.Context, encodedPrincipal string) context.Context {
	if tr, ok := transport.FromClientContext(ctx); ok {
		switch tr.Kind() {
		case transport.KindHTTP:
			tr.RequestHeader().Set(MetadataKey, encodedPrincipal)
		case transport.KindGRPC:
			return metadata.AppendToOutgoingContext(ctx, MetadataKey, encodedPrincipal)
		}
	}
	return ctx
}

// Extract extracts the encoded principal string from the incoming request context.
// It handles both HTTP and gRPC transports.
func Extract(ctx context.Context) (string, bool) {
	if tr, ok := transport.FromServerContext(ctx); ok {
		var encodedPrincipal string
		switch tr.Kind() {
		case transport.KindHTTP:
			encodedPrincipal = tr.RequestHeader().Get(MetadataKey)
		case transport.KindGRPC:
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				vals := md.Get(MetadataKey)
				if len(vals) > 0 {
					encodedPrincipal = vals[0]
				}
			}
		}
		if encodedPrincipal != "" {
			return encodedPrincipal, true
		}
	}
	return "", false
}

// InjectDomain injects an already encoded domain string into the outgoing request context.
// It handles both HTTP and gRPC transports.
func InjectDomain(ctx context.Context, domain string) context.Context {
	if tr, ok := transport.FromClientContext(ctx); ok {
		switch tr.Kind() {
		case transport.KindHTTP:
			tr.RequestHeader().Set(DomainMetadataKey, domain)
		case transport.KindGRPC:
			return metadata.AppendToOutgoingContext(ctx, DomainMetadataKey, domain)
		}
	}
	return ctx
}

// ExtractDomain extracts the encoded domain string from the incoming request context.
// It handles both HTTP and gRPC transports.
func ExtractDomain(ctx context.Context) (string, bool) {
	if tr, ok := transport.FromServerContext(ctx); ok {
		var domain string
		switch tr.Kind() {
		case transport.KindHTTP:
			domain = tr.RequestHeader().Get(DomainMetadataKey)
		case transport.KindGRPC:
			if md, ok := metadata.FromIncomingContext(ctx); ok {
				vals := md.Get(DomainMetadataKey)
				if len(vals) > 0 {
					domain = vals[0]
				}
			}
		}
		if domain != "" {
			return domain, true
		}
	}
	return "", false
}
