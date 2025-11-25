package request

import (
	"context"
	"fmt"
	"net/http"

	kratoserrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport"
	kratoshttp "github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc/metadata"

	securityifaces "github.com/origadmin/contrib/security" // Import the security package for the Request interface
)

// valueSource defines the common interface for extracting key-value pairs from different sources.
type valueSource interface {
	Get(key string) string
	Values(key string) []string
	GetAll() map[string][]string
}

// httpHeaderSource adapts an http.Header to the valueSource interface.
type httpHeaderSource struct {
	Header http.Header
}

// Values returns the values associated with the given key from the HTTP header.
func (p httpHeaderSource) Values(key string) []string {
	return p.Header[key]
}

// Get returns the first value associated with the given key from the HTTP header.
func (p httpHeaderSource) Get(key string) string {
	return p.Header.Get(key)
}

// GetAll returns all key-value pairs from the HTTP header.
func (p httpHeaderSource) GetAll() map[string][]string {
	return p.Header
}

// grpcMetadataSource adapts a grpc.Metadata to the valueSource interface.
type grpcMetadataSource struct {
	MD metadata.MD
}

// Values returns the values associated with the given key from the gRPC metadata.
func (p grpcMetadataSource) Values(key string) []string {
	return p.MD.Get(key)
}

// Get returns the first value associated with the given key from the gRPC metadata.
func (p grpcMetadataSource) Get(key string) string {
	values := p.MD.Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// GetAll returns all key-value pairs from the gRPC metadata.
func (p grpcMetadataSource) GetAll() map[string][]string {
	return p.MD
}

// transportHeaderSource adapts a kratos transport.Header to the valueSource interface.
// This can be used as a generic source for headers/metadata from Kratos transport.
type transportHeaderSource struct {
	Header transport.Header
}

// Get returns the first value associated with the given key from the transport header.
func (t transportHeaderSource) Get(key string) string {
	return t.Header.Get(key)
}

// Values returns the values associated with the given key from the transport header.
func (t transportHeaderSource) Values(key string) []string {
	return t.Header.Values(key)
}

// GetAll returns all key-value pairs from the transport header.
func (t transportHeaderSource) GetAll() map[string][]string {
	all := make(map[string][]string)      // Initialize map without a specific capacity for now
	for _, key := range t.Header.Keys() { // Use Keys() method to get all keys
		values := t.Header.Values(key) // Use Values(key) method to get corresponding values
		// Create a copy of the slice to prevent external modifications to the underlying slice
		vCopy := make([]string, len(values))
		copy(vCopy, values)
		all[key] = vCopy
	}
	return all
}

// serverRequest implements securityifaces.Request by wrapping a valueSource
// and providing context-specific information like Kind, Operation, Method, and RouteTemplate.
type serverRequest struct {
	kind          string
	operation     string
	method        string
	routeTemplate string
	delegate      valueSource
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

// Get returns the first value associated with the given key from the delegate valueSource.
func (c *serverRequest) Get(key string) string {
	if c.delegate != nil {
		return c.delegate.Get(key)
	}
	return ""
}

// Values returns the values associated with the given key from the delegate valueSource.
func (c *serverRequest) Values(key string) []string {
	if c.delegate != nil {
		return c.delegate.Values(key)
	}
	return nil
}

// GetAll returns all key-value pairs from the delegate valueSource.
func (c *serverRequest) GetAll() map[string][]string {
	if c.delegate != nil {
		return c.delegate.GetAll()
	}
	return nil
}

// NewFromHTTPRequest creates a securityifaces.Request from a standard http.Request.
// This is useful when the full Kratos transport context is not available or needed.
func NewFromHTTPRequest(r *http.Request) securityifaces.Request {
	return &serverRequest{
		kind:          "http",
		operation:     r.URL.Path, // Use the request URL path as the operation
		method:        r.Method,
		routeTemplate: "", // Route template cannot be determined from a raw http.Request
		delegate:      newHTTPHeaderSource(r),
	}
}

// NewFromGRPCMetadata creates a securityifaces.Request from gRPC metadata and a full method name.
// This is useful for gRPC requests when the full Kratos transport context is not available or needed.
func NewFromGRPCMetadata(md metadata.MD, fullMethodName string) securityifaces.Request {
	return &serverRequest{
		kind:          "grpc",
		operation:     fullMethodName,
		method:        "", // Not applicable for raw gRPC metadata
		routeTemplate: "", // Not applicable for raw gRPC metadata
		delegate:      newGRPCMetadataSource(md),
	}
}

// NewFromServerContext extracts a securityifaces.Request from the server context.
func NewFromServerContext(ctx context.Context) (securityifaces.Request, error) {
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return nil, kratoserrors.New(500, "TRANSPORT_CONTEXT_MISSING", "transport context is missing")
	}

	var (
		kind          = string(tr.Kind())
		operation     = tr.Operation()
		method        string
		routeTemplate string
		delegate      valueSource
		err           error
	)

	switch tr.Kind() {
	case transport.KindHTTP:
		if ht, ok := tr.(kratoshttp.Transporter); ok {
			req := ht.Request()
			delegate = newHTTPHeaderSource(req)
			method = req.Method
			// Kratos HTTP transport does not directly expose the matched route template
			// via the transport.Transporter interface or kratoshttp.Transporter.
			// If route template is needed, it would typically be stored in the request context
			// by a routing middleware. For now, it remains empty.
		} else {
			err = kratoserrors.New(500, "INVALID_HTTP_TRANSPORT", "invalid HTTP transport type")
		}
	case transport.KindGRPC:
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			delegate = newGRPCMetadataSource(md)
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
		delegate:      delegate,
	}, nil
}
