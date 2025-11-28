package principal

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/transport"                 // For Kratos transport types
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http" // For Kratos HTTP transport
	"google.golang.org/grpc/metadata"                          // For gRPC metadata

	"github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/request" // For request.NewFromHTTPRequest
	"github.com/origadmin/runtime/log"              // For logging warnings
)

// --- Principal Propagation ---

// PropagatePrincipalToClientContext prepares the context for an outgoing client request
// by injecting encoded Principal into transport-specific metadata/headers.
// The returned context should be used for the outgoing client call.
func PropagatePrincipalToClientContext(ctx context.Context, p security.Principal, pt PropagationType) context.Context {
	encodedPrincipal, encodeErr := EncodePrincipal(p)
	if encodeErr != nil {
		log.Warnf("failed to encode principal for client propagation: %v", encodeErr)
		return ctx
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
		ctx = NewContext(ctx, p) // Re-inject principal
		// Or pass encodedPrincipal via context to RoundTripper
		// For simplicity, we'll assume the NativeHTTP client has access to the principal via context
		// and the RoundTripper will then set the header.
	default:
		ctx = metadata.AppendToOutgoingContext(ctx, MetadataKey, encodedPrincipal)
	}
	return ctx
}

// ExtractPrincipalFromServerContext extracts Principal from incoming request's
// transport-specific metadata/headers and injects it into the context.
func ExtractPrincipalFromServerContext(ctx context.Context, pt PropagationType) (security.Principal, context.Context, error) {
	var encodedPrincipal string

	switch pt {
	case PropagationTypeKratos:
		if tr, ok := transport.FromServerContext(ctx); ok {
			encodedPrincipal = tr.RequestHeader().Get(MetadataKey)
		}

	case PropagationTypeHTTP:
		// For native HTTP server, we need the http.Request's header.
		// This function assumes the http.Request's header is somehow available in ctx,
		// or that this function is called from an http.Handler wrapper that provides the header.
		// For now, this is a placeholder. A more direct implementation would be in a native HTTP middleware.
		// Let's assume request.NewFromHTTPRequest or similar is used upstream to populate ctx with a security.Request that has headers.
		securityReq, reqErr := request.NewFromServerContext(ctx) // Re-use Kratos request helper
		if reqErr == nil {
			encodedPrincipal = securityReq.Get(MetadataKey)
		}
	default:
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if principals := md.Get(MetadataKey); len(principals) > 0 {
				encodedPrincipal = principals[0]
			}
		}
	}

	if encodedPrincipal != "" {
		p, decodeErr := DecodePrincipal(encodedPrincipal)
		if decodeErr != nil {
			log.Warnf("Failed to decode propagated principal: %v", decodeErr)
			return nil, ctx, decodeErr
		}
		if p != nil {
			ctx = NewContext(ctx, p)
			return p, ctx, nil
		}
	}

	// If no principal found in propagation, attempt authentication from raw credentials if applicable
	// This logic would typically be in authn middleware, not here in propagation helper.
	// For now, we only extract propagated 
	return nil, ctx, nil
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
		ctx = NewDomainContext(ctx, domain) // Assuming RoundTripper picks it up
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
		securityReq, reqErr := request.NewFromServerContext(ctx) // Re-use Kratos request helper
		if reqErr == nil {
			domain = securityReq.Get(DomainMetadataKey)
		}
	default:
		return "", ctx, fmt.Errorf("unsupported propagation type %s for Domain server extraction", pt.String())
	}

	if domain != "" {
		ctx = NewDomainContext(ctx, domain)
		return domain, ctx, nil
	}
	return "", ctx, nil
}
