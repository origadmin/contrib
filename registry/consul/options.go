/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package consul

import (
	"github.com/origadmin/runtime/extensions/optionutil"
	"github.com/origadmin/runtime/interfaces/options"
)

// optionsKey is a private key type to avoid collisions in context.
type optionsKey struct{}

// consulOptions holds specific options for the Consul options.
// Pointers are used to distinguish between a zero value and a value not being set.
type consulOptions struct {
	healthCheck                    bool
	heartbeat                      bool
	deregisterCriticalServiceAfter int
	healthCheckInterval            int
}

// WithHealthCheck is an option to enable/disable health check.
func WithHealthCheck(enable bool) options.Option {
	return optionutil.Update(func(o *consulOptions) {
		o.healthCheck = enable
	})
}

// WithHeartbeat is an option to enable/disable heartbeat.
func WithHeartbeat(enable bool) options.Option {
	return optionutil.Update(func(o *consulOptions) {
		o.heartbeat = enable
	})
}

// WithDeregisterCriticalServiceAfter is an option to set the deregister critical service after duration in seconds.
func WithDeregisterCriticalServiceAfter(seconds int) options.Option {
	return optionutil.Update(func(o *consulOptions) {
		o.deregisterCriticalServiceAfter = seconds
	})
}

// WithHealthCheckInterval is an option to set the health check interval in seconds.
func WithHealthCheckInterval(seconds int) options.Option {
	return optionutil.Update(func(o *consulOptions) {
		o.healthCheckInterval = seconds
	})
}

func fromOptions(opts []options.Option) *consulOptions {
	return optionutil.NewT[consulOptions](opts...)
}
