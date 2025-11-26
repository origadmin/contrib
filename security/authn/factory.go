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

// Factory is an interface for a provider factory that can create a Provider
// instance when given a runtime configuration. It's a stateless object
// intended to be registered at init time.
type Factory interface {
	// NewAuthenticator creates a new Provider instance using the provided configuration.
	NewAuthenticator(cfg *authnv1.Authenticator, opts ...options.Option) (Authenticator, error)
}

// FactoryFunc is a function type that creates a Provider instance.
type FactoryFunc func(config *authnv1.Authenticator, opts ...options.Option) (Authenticator, error)

func (f FactoryFunc) NewAuthenticator(cfg *authnv1.Authenticator, opts ...options.Option) (Authenticator, error) {
	return f(cfg, opts...)
}

var (
	mu               sync.RWMutex
	defaultFactories = make(map[string]Factory)
)

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
func New(cfg *authnv1.Authenticator, opts ...options.Option) (Authenticator, error) {
	mu.RLock()
	defer mu.RUnlock()
	factory, ok := defaultFactories[cfg.GetType()]
	if !ok {
		return nil, fmt.Errorf("authenticator factory %q not found", cfg.GetType())
	}
	return factory.NewAuthenticator(cfg, opts...)
}

// NewCredentialCreator is a convenience helper that creates a provider instance
// and directly returns its CredentialCreator capability.
// It returns an error if the specified provider does not support the CredentialCreator interface.
func NewCredentialCreator(cfg *authnv1.Authenticator, opts ...options.Option) (credential.Creator, error) {
	authn, err := New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	creator, ok := authn.(credential.Creator)
	if !ok {
		return nil, fmt.Errorf("authn %q does not support the CredentialCreator capability", cfg.GetType())
	}
	return creator, nil
}

// NewCredentialRevoker is a convenience helper that creates a provider instance
// and directly returns its CredentialRevoker capability.
// It returns an error if the specified provider does not support the CredentialRevoker interface.
func NewCredentialRevoker(cfg *authnv1.Authenticator, opts ...options.Option) (credential.Revoker, error) {
	authn, err := New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	revoker, ok := authn.(credential.Revoker)
	if !ok {
		return nil, fmt.Errorf("authn %q does not support the CredentialRevoker capability", cfg.GetType())
	}
	return revoker, nil
}
