/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package credential

import (
	securityifaces "github.com/origadmin/contrib/security" // Updated import path
	securityv1 "github.com/origadmin/contrib/security/api/gen/go/config/v1"
	"github.com/origadmin/contrib/security/meta" // Updated import path
)

// credentialResponse is the internal implementation of the security.CredentialResponse interface.
// It stores credential response data in a Go-idiomatic way.
type credentialResponse struct {
	crType  string
	payload *securityv1.Payload
	meta    map[string][]string // Directly store Go-idiomatic metadata
}

// NewCredentialResponse creates a CredentialResponse instance.
// It receives the final, prepared components in Go-idiomatic types.
func NewCredentialResponse(
	crType string,
	payload *securityv1.Payload,
	meta map[string][]string,
) securityifaces.CredentialResponse { // Use securityifaces.CredentialResponse
	return &credentialResponse{
		crType:  crType,
		payload: payload,
		meta:    meta,
	}
}

// Payload returns the payload of the credential.
func (c *credentialResponse) Payload() *securityv1.Payload {
	return c.payload
}

// GetType returns the type of the credential.
func (c *credentialResponse) GetType() string {
	return c.crType
}

// GetMeta returns the metadata associated with the credential response
// as a standard Go map[string][]string, for easy consumption.
func (c *credentialResponse) GetMeta() map[string][]string {
	return c.meta
}

// Response converts the CredentialResponse to its protobuf representation.
// This method performs the conversion from Go-idiomatic internal storage to Protobuf format.
func (c *credentialResponse) Response() *securityv1.CredentialResponse {
	// Convert Go-idiomatic metadata to Protobuf MetaValue map only when Response() is called.
	// Use the ToProto method on the meta.Meta type.
	protoMeta := meta.Meta(c.meta).ToProto()

	return &securityv1.CredentialResponse{
		Type:     c.crType,
		Payload:  c.payload,
		Metadata: protoMeta,
	}
}
