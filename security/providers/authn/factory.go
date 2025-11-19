/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package authn

import (
	"fmt"
	"sync"

	authnv1 "github.com/origadmin/contrib/security/api/gen/go/config/authn/v1"
	"github.com/origadmin/runtime/interfaces/options"
	// No need to import securityifaces here, as Provider and Factory are defined in this package.
)

var (
	mu        sync.RWMutex
	factories = make(map[string]Factory)
)

// Register registers a new authenticator provider factory.
// This function is intended to be called from the init() function of each provider implementation.
func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := factories[name]; ok {
		panic(fmt.Sprintf("authenticator factory %q already registered", name))
	}
	factories[name] = factory
}

// Create creates a new authenticator provider instance based on the given configuration.
// It looks up the appropriate factory using the type specified in the config and invokes it.
// The returned Provider instance is NOT stored globally; it is the caller's responsibility
// to manage its lifecycle and inject it where needed.
func Create(cfg *authnv1.Authenticator, opts ...options.Option) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	factory, ok := factories[cfg.GetType()]
	if !ok {
		return nil, fmt.Errorf("authenticator factory %q not found", cfg.GetType())
	}
	return factory(cfg, opts...)
}
