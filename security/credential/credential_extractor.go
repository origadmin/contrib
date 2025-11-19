/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package credential

import (
	"context"
	"strings"

	"google.golang.org/protobuf/proto"

	securityv1 "github.com/origadmin/contrib/api/gen/go/config/security/v1"
	"github.com/origadmin/runtime/errors"                               // This import needs to be handled carefully
	securityInterfaces "github.com/origadmin/contrib/security/security" // Updated import path
	"github.com/go-kratos/kratos/v2/transport"                          // Added missing import
)

const (
	// AuthorizationHeader is the canonical header name for authorization.
	AuthorizationHeader = "Authorization"
)

// HeaderCredentialExtractor implements the security.CredentialExtractor interface.
// It extracts credentials from the "Authorization" HTTP header.
type HeaderCredentialExtractor struct{}

// NewHeaderCredentialExtractor creates a new instance of HeaderCredentialExtractor.
func NewHeaderCredentialExtractor() securityInterfaces.CredentialExtractor { // Use securityInterfaces.CredentialExtractor
	return &HeaderCredentialExtractor{}
}

// Extract is responsible for all extraction and parsing logic. It prepares all
// necessary components and then calls the pure NewCredential constructor.
func (e *HeaderCredentialExtractor) Extract(ctx context.Context, request securityInterfaces.Request) (securityInterfaces.Credential, error) { // Use securityInterfaces.Request and securityInterfaces.Credential
	authHeader := request.Get(AuthorizationHeader)
	if authHeader == "" {
		return nil, errors.New(401, "AUTHORIZATION_HEADER_NOT_FOUND", "authorization header not found")
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil, errors.New(401, "INVALID_AUTHORIZATION_HEADER", "invalid authorization header format")
	}

	scheme := strings.TrimSpace(parts[0])
	rawCredential := strings.TrimSpace(parts[1])

	if scheme == "" || rawCredential == "" {
		return nil, errors.New(401, "INVALID_AUTHORIZATION_HEADER", "invalid authorization header format")
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
	// NewCredential is now defined in credential.go
	return NewCredential(credentialType, authHeader, payload, goMeta)
}

// NewEmptyCredential creates an empty credential for cases where no credential is found in the request.
func NewEmptyCredential() securityInterfaces.Credential {
	return &credential{
		credentialType: "none",
		rawCredential:  "",
		payload:        nil,
		meta:           nil,
	}
}

// ExtractFromTransport extracts credential from Kratos transport.
func ExtractFromTransport(tr transport.Transporter) (securityInterfaces.Credential, error) {
	// For gRPC, metadata is in tr.RequestHeader()
	// For HTTP, headers are in tr.RequestHeader()
	// This is a simplified example. A real implementation might need to check transport type.
	authHeader := tr.RequestHeader().Get(AuthorizationHeader)
	if authHeader == "" {
		return NewEmptyCredential(), nil // No credential found, return empty
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil, errors.New(401, "INVALID_AUTHORIZATION_HEADER", "invalid authorization header format")
	}

	scheme := strings.TrimSpace(parts[0])
	rawCredential := strings.TrimSpace(parts[1])

	if scheme == "" || rawCredential == "" {
		return nil, errors.New(401, "INVALID_AUTHORIZATION_HEADER", "invalid authorization header format")
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

	// Extract all headers as metadata
	metaMap := make(map[string][]string)
	for k, v := range tr.RequestHeader() {
		metaMap[k] = v
	}

	return NewCredential(credentialType, authHeader, payload, metaMap)
}
