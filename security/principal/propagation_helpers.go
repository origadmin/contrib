package principal

import (
	"context"
	"net/http"

	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/metadata"

	"github.com/origadmin/runtime/log"
)

// PropagateToClientContext prepares the context for an outgoing client request
// by injecting an encoded Principal string into transport-specific metadata/headers.
// Parameters are ordered by priority: PropagationType, Context, Principal data, optional Request.
func PropagateToClientContext(pt PropagationType, ctx context.Context, req any,
	encodedPrincipal string) context.Context {
	if encodedPrincipal == "" {
		return ctx // Nothing to propagate
	}

	switch pt {
	case PropagationTypeKratos:
		if tr, ok := transport.FromClientContext(ctx); ok {
			tr.RequestHeader().Set(MetadataKey, encodedPrincipal)
		}
	case PropagationTypeHTTP:
		if r, ok := req.(*http.Request); ok && r != nil {
			r.Header.Set(MetadataKey, encodedPrincipal)
		} else {
			log.Warnf("PropagationTypeHTTP requires a non-nil *http.Request passed as the 'req' parameter")
		}
	case PropagationTypeGRPC:
		fallthrough
	default: // Default behavior is gRPC
		ctx = metadata.AppendToOutgoingContext(ctx, MetadataKey, encodedPrincipal)
	}
	return ctx
}

// ExtractFromServerContext extracts an encoded principal string from an incoming request's
// transport-specific metadata/headers.
// Parameters are ordered by priority: PropagationType, Context, optional Request.
func ExtractFromServerContext(pt PropagationType, ctx context.Context, req any) string {
	var encodedPrincipal string

	switch pt {
	case PropagationTypeKratos:
		if tr, ok := transport.FromServerContext(ctx); ok {
			encodedPrincipal = tr.RequestHeader().Get(MetadataKey)
		}
	case PropagationTypeHTTP:
		if r, ok := req.(*http.Request); ok && r != nil {
			encodedPrincipal = r.Header.Get(MetadataKey)
		} else {
			log.Warnf("PropagationTypeHTTP requires a non-nil *http.Request passed as the 'req' parameter")
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

	return encodedPrincipal
}
