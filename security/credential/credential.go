/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package credential

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	securityifaces "github.com/origadmin/contrib/security" // Updated import path
	apikeyv1 "github.com/origadmin/contrib/security/api/gen/go/config/authn/apikey/v1"
	oidcv1 "github.com/origadmin/contrib/security/api/gen/go/config/authn/oidc/v1"
	securityv1 "github.com/origadmin/contrib/security/api/gen/go/config/v1"
	"github.com/origadmin/contrib/security/meta" // Updated import path
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
	// Use the ToProto method on the meta.Meta type.
	protoMeta := meta.Meta(c.meta).ToProto()

	return &securityv1.CredentialSource{
		Type:     c.credentialType,
		Raw:      c.rawCredential,
		Payload:  c.payload,
		Metadata: protoMeta,
	}
}

func PayloadBearerCredential(cred securityifaces.Credential) (*securityv1.BearerCredential, error) { // Use securityifaces.Credential
	if cred.Type() != "jwt" {
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
	if cred.Type() != "oidc" {
		return nil, fmt.Errorf("credential type is not oidc")
	}
	var oidc oidcv1.OidcCredential
	err := cred.ParsedPayload(&oidc)
	if err != nil {
		return nil, err
	}
	return &oidc, nil
}

func PayloadAPIKeyCredential(cred securityifaces.Credential) (*apikeyv1.KeyCredential, error) { // Use securityifaces.Credential
	if cred.Type() != "api_key" {
		return nil, fmt.Errorf("credential type is not api_key")
	}
	var apiKey apikeyv1.KeyCredential
	err := cred.ParsedPayload(&apiKey)
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}
