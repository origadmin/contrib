/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authz

import (
	"fmt"
	"sync"

	authzv1 "github.com/origadmin/contrib/api/gen/go/security/authz/v1"
	"github.com/origadmin/runtime/interfaces/options"
)

// Provider is an interface for a security component that can provide authorization capabilities.
type Provider interface {
	// Authorizer returns the Authorizer capability, if supported.
	Authorizer() (Authorizer, bool)
}

// Factory is a function type that creates a Provider instance.
type Factory func(config *authzv1.Authorizer, opts ...options.Option) (Provider, error)

var (
	mu               sync.RWMutex
	defaultFactories = make(map[string]Factory)
)

// Register registers a new authorizer provider factory.
// This function is intended to be called from the init() function of each provider implementation.
func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := defaultFactories[name]; ok {
		panic(fmt.Sprintf("authorizer factory %q already registered", name))
	}
	defaultFactories[name] = factory
}

// New creates a new authorizer provider instance based on the given configuration.
// It looks up the appropriate factory using the type specified in the config and invokes it.
// The returned Provider instance is NOT stored globally; it is the caller's responsibility
// to manage its lifecycle and inject it where needed.
func New(cfg *authzv1.Authorizer, opts ...options.Option) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	factory, ok := defaultFactories[cfg.GetType()]
	if !ok {
		return nil, fmt.Errorf("authorizer factory %q not found", cfg.GetType())
	}
	return factory(cfg, opts...)
}
