/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package security provides declarative security interfaces for authentication and authorization.
package security

import (
	securityv1 "github.com/origadmin/runtime/api/gen/go/config/security/v1"
)

// CredentialResponse represents a credential structure intended for
// transmission to clients (e.g., frontend applications).
type CredentialResponse interface {
	// GetType returns the type of the credential.
	GetType() string

	// Payload returns the payload of the credential.
	// This should ideally return a structured type or a proto.Message.
	Payload() *securityv1.Payload

	// GetMeta returns the metadata associated with the credential response
	// as a standard Go map[string][]string, for easy consumption.
	GetMeta() map[string][]string

	// Response returns the canonical Protobuf representation of the credential response.
	// This allows direct access to the underlying protobuf message for serialization.
	Response() *securityv1.CredentialResponse
}
