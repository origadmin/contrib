package credential

import (
	"fmt"
	"strings"

	"github.com/go-kratos/kratos/v2/transport"
	"github.com/origadmin/runtime/context"
	"github.com/origadmin/runtime/errors"
	"google.golang.org/protobuf/proto"

	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	securityifaces "github.com/origadmin/contrib/security"
)

const (
	// AuthorizationHeader is the canonical header name for authorization.
	AuthorizationHeader = "Authorization"
)

// ExtractFromTransport extracts a security.Credential from a Kratos transport.Transporter.
// It handles both HTTP and gRPC transports uniformly via the transport.Transporter interface.
func ExtractFromTransport(tr transport.Transporter) (securityifaces.Credential, error) {
	authHeader := tr.RequestHeader().Get(AuthorizationHeader)
	if authHeader == "" {
		return NewEmptyCredential(), nil
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid authorization header format") // Return error for malformed header
	}

	scheme := strings.TrimSpace(parts[0])
	rawCredential := strings.TrimSpace(parts[1])

	if scheme == "" || rawCredential == "" {
		return nil, fmt.Errorf("invalid authorization header format") // Return error for empty scheme or raw credential
	}

	var credentialType string
	var payload proto.Message
	switch strings.ToLower(scheme) {
	case "bearer":
		credentialType = "jwt"
		payload = &securityv1.BearerCredential{
			Token: rawCredential,
		}
	default:
		credentialType = scheme
	}

	// For now, we don't extract additional metadata from the transport header here.
	// If needed, it can be added, but for basic token extraction, it's not required.
	return NewCredential(credentialType, rawCredential, payload, nil)
}

// ExtractFromRequest extracts a security.Credential from a security.Request.
// It is responsible for all extraction and parsing logic, preparing all
// necessary components and then calling the pure NewCredential constructor.
func ExtractFromRequest(ctx context.Context, request securityifaces.Request) (securityifaces.Credential, error) {
	authHeader := request.Get(AuthorizationHeader)
	if authHeader == "" {
		return NewEmptyCredential(), nil // Return empty credential if no Authorization header
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil, errors.New(401, "INVALID_AUTHORIZATION_HEADER", "invalid authorization header format") // Return error for malformed header
	}

	scheme := strings.TrimSpace(parts[0])
	rawCredential := strings.TrimSpace(parts[1])

	if scheme == "" || rawCredential == "" {
		return nil, errors.New(401, "INVALID_AUTHORIZATION_HEADER", "invalid authorization header format") // Return error for empty scheme or raw credential
	}

	// Prepare all components for the constructor
	var credentialType string
	var payload proto.Message
	switch strings.ToLower(scheme) {
	case "bearer":
		credentialType = "jwt"
		payload = &securityv1.BearerCredential{
			Token: rawCredential,
		}
	default:
		credentialType = scheme
	}

	// Directly get Go-idiomatic metadata from the request.
	goMeta := request.GetAll()

	// Call the pure constructor with the final, prepared components.
	return NewCredential(credentialType, rawCredential, payload, goMeta)
}
