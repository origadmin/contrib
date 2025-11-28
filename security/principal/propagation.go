package principal

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	securityifaces "github.com/origadmin/contrib/security" // Updated import path
	"github.com/origadmin/runtime/context"
	"github.com/origadmin/runtime/log"
)

const (
	// MetadataKey is the key used to store the Principal in gRPC metadata or HTTP headers.
	MetadataKey = "x-md-global-principal-proto"
	// DomainMetadataKey is the key used to store the Domain in gRPC metadata or HTTP headers.
	DomainMetadataKey = "x-md-global-domain"
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

// PropagatePrincipalToGRPCClient extracts Principal from ctx and appends to outgoing gRPC metadata.
func PropagatePrincipalToGRPCClient(ctx context.Context) context.Context {
	if p, ok := FromContext(ctx); ok {
		encodedPrincipal, encodeErr := EncodePrincipal(p)
		if encodeErr != nil {
			log.Warnf("failed to encode principal for gRPC client: %v", encodeErr)
		} else {
			ctx = metadata.AppendToOutgoingContext(ctx, MetadataKey, encodedPrincipal)
		}
	}
	return ctx
}

// ExtractPrincipalFromGRPCServer extracts Principal from incoming gRPC metadata and injects into ctx.
func ExtractPrincipalFromGRPCServer(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	encodedPrincipal := md.Get(MetadataKey)
	if len(encodedPrincipal) > 0 {
		p, err := DecodePrincipal(encodedPrincipal[0])
		if err != nil {
			log.Warnf("Failed to decode propagated principal from gRPC metadata: %v", err)
		} else if p != nil {
			ctx = NewContext(ctx, p)
		}
	}
	return ctx
}

// PropagatePrincipalToHTTPClient extracts Principal from ctx and adds to HTTP headers.
func PropagatePrincipalToHTTPClient(ctx context.Context, header http.Header) {
	if p, ok := FromContext(ctx); ok {
		encodedPrincipal, encodeErr := EncodePrincipal(p)
		if encodeErr != nil {
			log.Warnf("failed to encode principal for HTTP client: %v", encodeErr)
		} else {
			header.Set(MetadataKey, encodedPrincipal)
		}
	}
}

// ExtractPrincipalFromHTTPServer extracts Principal from HTTP headers and injects into ctx.
func ExtractPrincipalFromHTTPServer(ctx context.Context, header http.Header) context.Context {
	encodedPrincipal := header.Get(MetadataKey)
	if encodedPrincipal != "" {
		p, err := DecodePrincipal(encodedPrincipal)
		if err != nil {
			log.Warnf("Failed to decode propagated principal from HTTP header: %v", err)
		} else if p != nil {
			ctx = NewContext(ctx, p)
		}
	}
	return ctx
}

// --- Domain Propagation Functions ---

// PropagateDomainToGRPCClient extracts Domain from ctx and appends to outgoing gRPC metadata.
func PropagateDomainToGRPCClient(ctx context.Context) context.Context {
	if domain, ok := DomainFromContext(ctx); ok && domain != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, DomainMetadataKey, domain)
	}
	return ctx
}

// ExtractDomainFromGRPCServer extracts Domain from incoming gRPC metadata and injects into ctx.
func ExtractDomainFromGRPCServer(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	domains := md.Get(DomainMetadataKey)
	if len(domains) > 0 && domains[0] != "" {
		ctx = NewDomainContext(ctx, domains[0])
	}
	return ctx
}

// PropagateDomainToHTTPClient extracts Domain from ctx and adds to HTTP headers.
func PropagateDomainToHTTPClient(ctx context.Context, header http.Header) {
	if domain, ok := DomainFromContext(ctx); ok && domain != "" {
		header.Set(DomainMetadataKey, domain)
	}
}

// ExtractDomainFromHTTPServer extracts Domain from HTTP headers and injects into ctx.
func ExtractDomainFromHTTPServer(ctx context.Context, header http.Header) context.Context {
	domain := header.Get(DomainMetadataKey)
	if domain != "" {
		ctx = NewDomainContext(ctx, domain)
	}
	return ctx
}
