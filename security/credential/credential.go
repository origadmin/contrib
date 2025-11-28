/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package credential

import (
	"fmt"
	"strings" // Added for string manipulation

	"google.golang.org/grpc/metadata" // Added for gRPC metadata extraction

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	apikeyv1 "github.com/origadmin/contrib/api/gen/go/security/authn/apikey/v1"
	oidcv1 "github.com/origadmin/contrib/api/gen/go/security/authn/oidc/v1"
	securityv1 "github.com/origadmin/contrib/api/gen/go/security/v1"
	securityifaces "github.com/origadmin/contrib/security"
	"github.com/origadmin/contrib/security/request"
)

const (
	// BearerCredentialType represents the type for bearer tokens (e.g., JWT).
	BearerCredentialType = "jwt"

	// OIDCCredentialType represents the type for OpenID Connect (OIDC) tokens.
	OIDCCredentialType = "oidc"

	// APIKeyCredentialType represents the type for API keys.
	APIKeyCredentialType = "api_key"
)

// credential is the concrete implementation of the security.Credential interface.
// It stores credential data in a Go-idiomatic way.
type credential struct {
	credentialType string
	rawCredential  string
	payload        *anypb.Any
	meta           map[string][]string // Directly store Go-idiomatic metadata
}

// NewCredential is a pure constructor for creating a new Credential instance.
// It receives the final, prepared components in Go-idiomatic types.
func NewCredential(
	credentialType string,
	rawCredential string,
	payload proto.Message,
	meta map[string][]string, // Receives Go-idiomatic metadata
) (securityifaces.Credential, error) { // Use securityifaces.Credential
	// Convert payload to Any type
	var anyPayload *anypb.Any
	if payload != nil {
		var err error
		anyPayload, err = anypb.New(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload to anypb.Any: %w", err)
		}
	}

	return &credential{
		credentialType: credentialType,
		rawCredential:  rawCredential,
		payload:        anyPayload,
		meta:           meta,
	}, nil
}

// NewEmptyCredential creates and returns an empty, unauthenticated credential.
func NewEmptyCredential() securityifaces.Credential {
	return &credential{
		credentialType: "none",
		rawCredential:  "",
		payload:        nil,
		meta:           nil,
	}
}

// Type returns the type of the credential.
func (c *credential) Type() string {
	return c.credentialType
}

// Raw returns the original, unparsed credential string.
func (c *credential) Raw() string {
	return c.rawCredential
}

// ParsedPayload unmarshals the credential's payload into the provided protobuf message.
func (c *credential) ParsedPayload(message proto.Message) error {
	if c.payload == nil {
		return fmt.Errorf("credential payload is nil")
	}
	return c.payload.UnmarshalTo(message)
}

// GetMeta returns the authentication-related metadata associated with the credential
// as a standard Go map[string][]string, for easy consumption by Authenticator implementations.
func (c *credential) GetMeta() map[string][]string {
	return c.meta
}

// Source returns the canonical Protobuf representation of the credential.
// This method performs the conversion from Go-idiomatic internal storage to Protobuf format.
func (c *credential) Source() *securityv1.CredentialSource {
	// Convert Go-idiomatic metadata to Protobuf MetaValue map only when Source() is called.
	// Use the ToProto method on the request.Metadata type.
	protoMeta := request.Metadata(c.meta).ToProto()

	return &securityv1.CredentialSource{
		Type:     c.credentialType,
		Raw:      c.rawCredential,
		Payload:  c.payload,
		Metadata: protoMeta,
	}
}

// ExtractFromGRPCMetadata extracts a security.Credential from gRPC incoming metadata.
// It looks for the "authorization" header (case-insensitive) and attempts to parse a Bearer token.
// If a Bearer token is found, it returns a credential of BearerCredentialType.
// If no valid credential is found, it returns NewEmptyCredential().
func ExtractFromGRPCMetadata(md metadata.MD) (securityifaces.Credential, error) {
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return NewEmptyCredential(), nil // No authorization header, return empty credential.
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return NewEmptyCredential(), nil // Not a Bearer token, return empty credential.
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return NewEmptyCredential(), nil // Empty token string, return empty credential.
	}

	bearerPayload := &securityv1.BearerCredential{Token: token}
	cred, err := NewCredential(BearerCredentialType, token, bearerPayload, nil) // No additional metadata for now
	if err != nil {
		return nil, fmt.Errorf("failed to create bearer credential from gRPC metadata: %w", err)
	}
	return cred, nil
}

func PayloadBearerCredential(cred securityifaces.Credential) (*securityv1.BearerCredential, error) { // Use securityifaces.Credential
	if cred.Type() != BearerCredentialType {
		return nil, fmt.Errorf("credential type is not jwt")
	}
	var bearer securityv1.BearerCredential
	err := cred.ParsedPayload(&bearer)
	if err != nil {
		return nil, err
	}
	return &bearer, nil
}

func PayloadOIDCCredential(cred securityifaces.Credential) (*oidcv1.OidcCredential, error) { // Use securityifaces.Credential

	if cred.Type() != OIDCCredentialType {
		return nil, fmt.Errorf("credential type is not %s", OIDCCredentialType)
	}
	var oidc oidcv1.OidcCredential
	err := cred.ParsedPayload(&oidc)
	if err != nil {
		return nil, err
	}
	return &oidc, nil
}

func PayloadAPIKeyCredential(cred securityifaces.Credential) (*apikeyv1.KeyCredential, error) { // Use securityifaces.Credential
	if cred.Type() != APIKeyCredentialType {
		return nil, fmt.Errorf("credential type is not %s", APIKeyCredentialType)
	}
	var apiKey apikeyv1.KeyCredential
	err := cred.ParsedPayload(&apiKey)
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}
