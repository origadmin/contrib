/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	"fmt"
	"sync"

	authnv1 "github.com/origadmin/contrib/api/gen/go/security/authn/v1"
	"github.com/origadmin/contrib/security/credential"
	"github.com/origadmin/runtime/interfaces/options"
)

// Provider is an interface for a security component that can provide various authentication-related capabilities.
type Provider interface {
	// Authenticator returns the Authenticator capability, if supported.
	Authenticator() (Authenticator, bool)
	// CredentialCreator returns the CredentialCreator capability, if supported.
	CredentialCreator() (credential.Creator, bool)
	// CredentialRevoker returns the CredentialRevoker capability, if supported.
	CredentialRevoker() (credential.Revoker, bool)
}

// FactoryFunc is a function type that creates a Provider instance.
type FactoryFunc func(config *authnv1.Authenticator, opts ...options.Option) (Provider, error)

var (
	mu               sync.RWMutex
	defaultFactories = make(map[string]Factory)
)

// Factory is an interface for a provider factory that can create a Provider
// instance when given a runtime configuration. It's a stateless object
// intended to be registered at init time.
type Factory interface {
	// NewProvider creates a new Provider instance using the provided configuration.
	NewProvider(cfg *authnv1.Authenticator, opts ...options.Option) (Provider, error)
}

// Register registers a new authenticator provider blueprint.
// This function is intended to be called from the init() function of each provider implementation.
func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := defaultFactories[name]; ok {
		panic(fmt.Sprintf("authenticator factory %q already registered", name))
	}
	defaultFactories[name] = factory
}

// New creates a new authenticator provider instance based on the given configuration.
// It looks up the appropriate factory using the type specified in the config and invokes it.
// The returned Provider instance is NOT stored globally; it is the caller's responsibility
// to manage its lifecycle and inject it where needed.
func New(cfg *authnv1.Authenticator, opts ...options.Option) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	factory, ok := defaultFactories[cfg.GetType()]
	if !ok {
		return nil, fmt.Errorf("authenticator factory %q not found", cfg.GetType())
	}
	return factory.NewProvider(cfg, opts...)
}
