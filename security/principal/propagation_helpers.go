package principal

import (
	"context"

	"github.com/go-kratos/kratos/v2/transport" // For Kratos transport types
	"google.golang.org/grpc/metadata"          // For gRPC metadata

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
func ExtractFromServerContext(ctx context.Context, pt PropagationType) (string, context.Context) {
	var encodedPrincipal string

	switch pt {
	case PropagationTypeKratos:
		if tr, ok := transport.FromServerContext(ctx); ok {
			encodedPrincipal = tr.RequestHeader().Get(MetadataKey)
		}
	case PropagationTypeHTTP:
		securityReq, reqErr := request.NewFromServerContext(ctx)
		if reqErr == nil {
			encodedPrincipal = securityReq.Get(MetadataKey)
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
			}
		}
	}

	return encodedPrincipal, ctx
}
