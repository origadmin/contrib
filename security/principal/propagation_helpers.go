package principal

import (
	"context"

	"github.com/go-kratos/kratos/v2/transport"                 // For Kratos transport types
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http" // For Kratos HTTP transport
	"google.golang.org/grpc/metadata"                          // For gRPC metadata

	"github.com/origadmin/contrib/security/request" // For request.NewFromHTTPRequest
	"github.com/origadmin/runtime/log"              // For logging warnings
)

// --- Principal Propagation ---

// PropagateToClientContext prepares the context for an outgoing client request
// by injecting an encoded Principal string into transport-specific metadata/headers.
// The returned context should be used for the outgoing client call.
func PropagateToClientContext(ctx context.Context, encodedPrincipal string, pt PropagationType) context.Context {
	if encodedPrincipal == "" {
		return ctx // Nothing to propagate
	}

	switch pt {
	case PropagationTypeKratos:
		if tr, ok := transport.FromClientContext(ctx); ok {
			tr.RequestHeader().Set(MetadataKey, encodedPrincipal)
		}
	case PropagationTypeHTTP:
		// For native HTTP client round trippers, we can't modify http.Request directly here.
		// This should be handled by a specific RoundTripper implementation.
		// This function primarily prepares the context.
		// For now, let's inject into context, expecting a RoundTripper to pick it up.
		// The RoundTripper will then set the header using the encodedPrincipal from context.
		ctx = context.WithValue(ctx, MetadataKey, encodedPrincipal) // Store encoded string in context
	case PropagationTypeGRPC:
		fallthrough
	default: // Default behavior is gRPC
		ctx = metadata.AppendToOutgoingContext(ctx, MetadataKey, encodedPrincipal)
	}
	return ctx
}

// ExtractFromServerContext extracts an encoded principal string from an incoming request's
// transport-specific metadata/headers.
func ExtractFromServerContext(ctx context.Context, pt PropagationType) (string, bool) {
	var encodedPrincipal string
	found := false

	switch pt {
	case PropagationTypeKratos:
		if tr, ok := transport.FromServerContext(ctx); ok {
			if val := tr.RequestHeader().Get(MetadataKey); val != "" {
				encodedPrincipal = val
				found = true
			}
		}
	case PropagationTypeHTTP:
		securityReq, reqErr := request.NewFromServerContext(ctx)
		if reqErr == nil {
			if val := securityReq.Get(MetadataKey); val != "" {
				encodedPrincipal = val
				found = true
			}
		} else {
			log.Warnf("failed to create security request from context for principal extraction: %v", reqErr)
		}
	case PropagationTypeGRPC:
		fallthrough
	default: // Default behavior is gRPC
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if principals := md.Get(MetadataKey); len(principals) > 0 {
				encodedPrincipal = principals[0]
				found = true
			}
		}
	}

	return encodedPrincipal, found
}

// --- Domain Propagation ---

// PropagateDomainToClientContext prepares the context for an outgoing client request
// by injecting domain into transport-specific metadata/headers.
func PropagateDomainToClientContext(ctx context.Context, domain string, pt PropagationType) context.Context {
	if domain == "" {
		return ctx
	}

	switch pt {
	case PropagationTypeKratos:
		if tr, ok := transport.FromClientContext(ctx); ok {
			tr.RequestHeader().Set(DomainMetadataKey, domain)
		}
	case PropagationTypeGRPC:
		ctx = metadata.AppendToOutgoingContext(ctx, DomainMetadataKey, domain)
	case PropagationTypeHTTP:
		ctx = context.WithValue(ctx, DomainMetadataKey, domain) // Store domain string in context
	default:
		log.Warnf("Unsupported propagation type %s for Domain client propagation", pt.String())
	}
	return ctx
}

// ExtractDomainFromServerContext extracts Domain from incoming request's
// transport-specific metadata/headers and injects it into the context.
func ExtractDomainFromServerContext(ctx context.Context, pt PropagationType) (string, context.Context, error) {
	var domain string
	switch pt {
	case PropagationTypeKratos:
		if tr, ok := transport.FromServerContext(ctx); ok {
			if ht, isHttp := tr.(kratoshttp.Transporter); isHttp {
				domain = ht.Request().Header.Get(DomainMetadataKey)
			}
		}
	case PropagationTypeGRPC:
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if domains := md.Get(DomainMetadataKey); len(domains) > 0 {
				domain = domains[0]
			}
		}
	case PropagationTypeHTTP:
		securityReq, reqErr := request.NewFromServerContext(ctx)
		if reqErr == nil {
			domain = securityReq.Get(DomainMetadataKey)
		}
	default:
		log.Warnf("Unsupported propagation type %s for Domain server extraction", pt.String())
		return "", ctx, nil
	}

	if domain != "" {
		ctx = NewDomainContext(ctx, domain)
		return domain, ctx, nil
	}
	return "", ctx, nil
}
