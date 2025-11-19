/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package security implements the functions, types, and interfaces for the module.
package security

import (
	"google.golang.org/protobuf/proto" // Import proto for proto.Message

	securityv1 "github.com/origadmin/contrib/api/gen/go/config/security/v1"
)

// Credential represents a credential, either received from a request or newly issued.
// It provides a unified interface to access credential data and its canonical Protobuf representation.
type Credential interface {
	// Type returns the type of the credential (e.g., "jwt", "apikey").
	Type() string

	// Raw returns the original, unparsed credential string.
	// For example, the full "Bearer eyJ..." JWT string, or the API key string.
	Raw() string

	// ParsedPayload unmarshals the credential's payload into the provided protobuf message.
	// This allows for type-safe unpacking of the payload into specific protobuf messages.
	ParsedPayload(message proto.Message) error

	// GetMeta returns the authentication-related metadata associated with the credential
	// as a standard Go map[string][]string, for easy consumption by Authenticator implementations.
	// This metadata is typically extracted and processed from the request context.
	GetMeta() map[string][]string

	// Source returns the canonical Protobuf representation of the credential.
	// This is essential for transmitting the credential data, for example, in a CredentialResponse.
	Source() *securityv1.CredentialSource
}
