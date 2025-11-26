package request

import (
	"context"
	"fmt"
	"net/http"

	kratoserrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc/metadata"

	"github.com/origadmin/contrib/security"
)

// serverRequest implements security.Request by wrapping Metadata
// and providing context-specific information like Kind, Operation, Method, and RouteTemplate.
type serverRequest struct {
	kind          string
	operation     string
	method        string
	routeTemplate string
	metadata      Metadata
}

// Kind returns the type of the request as a string (e.g., "grpc", "http").
func (c *serverRequest) Kind() string {
	return c.kind
}

// GetOperation returns the primary identifier for the logical operation being performed.
func (c *serverRequest) GetOperation() string {
	return c.operation
}

// GetMethod returns the HTTP verb (e.g., "GET", "POST") if the request is an HTTP call.
func (c *serverRequest) GetMethod() string {
	return c.method
}

// GetRouteTemplate returns the matched HTTP route template (e.g., "/v1/users/{id}")
// if the request is an HTTP call and a route template was matched.
func (c *serverRequest) GetRouteTemplate() string {
	return c.routeTemplate
}

// Get returns the first value associated with the given key from the metadata.
func (c *serverRequest) Get(key string) string {
	return c.metadata.Get(key)
}

// Values returns the values associated with the given key from the metadata.
func (c *serverRequest) Values(key string) []string {
	return c.metadata.Values(key)
}

// GetAll returns all key-value pairs from the metadata.
func (c *serverRequest) GetAll() map[string][]string {
	return c.metadata.GetAll()
}

// NewFromHTTPRequest creates a security.Request from a standard http.Request.
// This is useful when the full Kratos transport context is not available or needed.
func NewFromHTTPRequest(r *http.Request) security.Request {
	return &serverRequest{
		kind:          "http",
		operation:     r.URL.Path, // Use the request URL path as the operation
		method:        r.Method,
		routeTemplate: "", // Route template cannot be determined from a raw http.Request
		metadata:      FromHTTP(r.Header),
	}
}

// NewFromGRPCMetadata creates a security.Request from gRPC metadata and a full method name.
// This is useful for gRPC requests when the full Kratos transport context is not available or needed.
func NewFromGRPCMetadata(md metadata.MD, fullMethodName string) security.Request {
	return &serverRequest{
		kind:          "grpc",
		operation:     fullMethodName,
		method:        "", // Not applicable for raw gRPC metadata
		routeTemplate: "", // Not applicable for raw gRPC metadata
		metadata:      FromGRPC(md),
	}
}

// NewFromServerContext extracts a security.Request from the server context.
func NewFromServerContext(ctx context.Context) (security.Request, error) {
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return nil, kratoserrors.New(500, "TRANSPORT_CONTEXT_MISSING", "transport context is missing")
	}

	var (
		kind          string
		operation     = tr.Operation()
		method        string
		routeTemplate string
		meta          Metadata
		err           error
	)

	switch tr.Kind() {
	case transport.KindHTTP:
		kind = "http"
		if ht, ok := tr.(kratoshttp.Transporter); ok {
			req := ht.Request()
			meta = FromHTTP(req.Header)
			method = req.Method
			// Kratos HTTP transport does not directly expose the matched route template
			// via the transport.Transporter interface or kratoshttp.Transporter.
			// If route template is needed, it would typically be stored in the request context
			// by a routing middleware. For now, it remains empty.
		} else {
			err = kratoserrors.New(500, "INVALID_HTTP_TRANSPORT", "invalid HTTP transport type")
		}
	case transport.KindGRPC:
		kind = "grpc"
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			meta = FromGRPC(md)
			// For gRPC, method and routeTemplate are typically derived from the operation
			// or are not directly applicable in the same way as HTTP.
		} else {
			err = kratoserrors.New(400, "NO_METADATA", "no metadata found in context")
		}
	default:
		err = fmt.Errorf("unsupported transport type: %v", tr.Kind())
	}

	if err != nil {
		return nil, err
	}

	return &serverRequest{
		kind:          kind,
		operation:     operation,
		method:        method,
		routeTemplate: routeTemplate,
		metadata:      meta,
	}, nil
}
