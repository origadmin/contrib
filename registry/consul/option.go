/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package consul

import (
	"context"

	"github.com/origadmin/runtime/registry"
)

// optionsKey is a private key type to avoid collisions in context.
type optionsKey struct{}

// consulOptions holds specific options for the Consul registry.
// Pointers are used to distinguish between a zero value and a value not being set.
type consulOptions struct {
	healthCheck                    *bool
	heartbeat                      *bool
	deregisterCriticalServiceAfter *int
	healthCheckInterval            *int
}

// WithHealthCheck is an option to enable/disable health check.
func WithHealthCheck(enable bool) registry.Option {
	return func(o *registry.Options) {
		if o.Context == nil {
			o.Context = context.Background()
		}
		opts, _ := o.Context.Value(optionsKey{}).(consulOptions)
		opts.healthCheck = &enable
		o.Context = context.WithValue(o.Context, optionsKey{}, opts)
	}
}

// WithHeartbeat is an option to enable/disable heartbeat.
func WithHeartbeat(enable bool) registry.Option {
	return func(o *registry.Options) {
		if o.Context == nil {
			o.Context = context.Background()
		}
		opts, _ := o.Context.Value(optionsKey{}).(consulOptions)
		opts.heartbeat = &enable
		o.Context = context.WithValue(o.Context, optionsKey{}, opts)
	}
}

// WithDeregisterCriticalServiceAfter is an option to set the deregister critical service after duration in seconds.
func WithDeregisterCriticalServiceAfter(seconds int) registry.Option {
	return func(o *registry.Options) {
		if o.Context == nil {
			o.Context = context.Background()
		}
		opts, _ := o.Context.Value(optionsKey{}).(consulOptions)
		d := seconds
		opts.deregisterCriticalServiceAfter = &d
		o.Context = context.WithValue(o.Context, optionsKey{}, opts)
	}
}

// WithHealthCheckInterval is an option to set the health check interval in seconds.
func WithHealthCheckInterval(seconds int) registry.Option {
	return func(o *registry.Options) {
		if o.Context == nil {
			o.Context = context.Background()
		}
		opts, _ := o.Context.Value(optionsKey{}).(consulOptions)
		d := seconds
		opts.healthCheckInterval = &d
		o.Context = context.WithValue(o.Context, optionsKey{}, opts)
	}
}
