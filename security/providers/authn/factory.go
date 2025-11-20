/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	"fmt"
	"sync"

	securityv1 "github.com/origadmin/contrib/security/api/gen/go/config/v1"
	"github.com/origadmin/runtime/interfaces/options"
	// No need to import securityifaces here, as Provider and Factory are defined in this package.
)

var (
	mu        sync.RWMutex
	blueprints = make(map[string]Blueprint)
)

// Blueprint is an interface for a provider factory that can create a Provider
// instance when given a runtime configuration. It's a stateless object
// intended to be registered at init time.
type Blueprint interface {
	// NewProvider creates a new Provider instance using the provided configuration.
	NewProvider(cfg *securityv1.Security, opts ...options.Option) (Provider, error)
}

// Register registers a new authenticator provider blueprint.
// This function is intended to be called from the init() function of each provider implementation.
func Register(name string, blueprint Blueprint) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := blueprints[name]; ok {
		panic(fmt.Sprintf("authenticator factory %q already registered", name))
	}
	blueprints[name] = blueprint
}

// Create creates a new authenticator provider instance based on the given configuration.
// It looks up the appropriate factory using the type specified in the config and invokes it.
// The returned Provider instance is NOT stored globally; it is the caller's responsibility
// to manage its lifecycle and inject it where needed.
func Create(cfg *securityv1.Security, opts ...options.Option) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	blueprint, ok := blueprints[cfg.GetAuthn().GetType()]
	if !ok {
		return nil, fmt.Errorf("authenticator factory %q not found", cfg.GetAuthn().GetType())
	}
	return blueprint.NewProvider(cfg, opts...)
}
