/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package consul

import (
	kratosconsul "github.com/go-kratos/kratos/contrib/registry/consul/v2"
	"github.com/goexts/generic/configure"
	"github.com/hashicorp/consul/api"

	configv1 "github.com/origadmin/runtime/api/gen/go/config/v1"
	"github.com/origadmin/runtime/registry"
	"github.com/origadmin/toolkits/errors"
)

// factory implements the registry.Factory interface for Consul.
type factory struct{}

func init() {
	// The const 'Type' is defined in 'consul.go' as `const Type = "consul"`.
	registry.Register(Type, &factory{})
}

// newClient creates a new Consul API client from the given configuration.
func newClient(cfg *configv1.Discovery) (*api.Client, error) {
	if cfg == nil || cfg.GetConsul() == nil {
		return nil, errors.New("consul configuration is missing")
	}

	consulCfg := cfg.GetConsul()
	apiConfig := api.DefaultConfig()

	if consulCfg.Address != "" {
		apiConfig.Address = consulCfg.Address
	}
	if consulCfg.Scheme != "" {
		apiConfig.Scheme = consulCfg.Scheme
	}
	if consulCfg.Datacenter != "" {
		apiConfig.Datacenter = consulCfg.Datacenter
	}
	if consulCfg.Token != "" {
		apiConfig.Token = consulCfg.Token
	}

	return api.NewClient(apiConfig)
}

// buildKratosOptions converts config and programmatic options into Kratos-Consul options.
func buildKratosOptions(cfg *configv1.Discovery, opts ...registry.Option) []kratosconsul.Option {
	// Apply programmatic options to a registry.Options struct to populate the context.
	regOpts := configure.Apply(&registry.Options{}, opts)
	for _, o := range opts {
		o(regOpts)
	}

	var progOpts consulOptions
	if regOpts.Context != nil {
		if co, ok := regOpts.Context.Value(optionsKey{}).(consulOptions); ok {
			progOpts = co
		}
	}

	kratosOpts := []kratosconsul.Option{}
	consulCfg := cfg.GetConsul()

	// Determine final values, with programmatic options taking precedence over config files.
	var (
		healthCheck                    bool
		heartbeat                      bool
		healthCheckInterval            int
		deregisterCriticalServiceAfter int
	)

	if consulCfg != nil {
		healthCheck = consulCfg.HealthCheck
		heartbeat = consulCfg.HeartBeat
		healthCheckInterval = int(consulCfg.GetHealthCheckInterval())
		deregisterCriticalServiceAfter = int(consulCfg.GetDeregisterCriticalServiceAfter())
	}

	if progOpts.healthCheck != nil {
		healthCheck = *progOpts.healthCheck
	}
	if progOpts.heartbeat != nil {
		heartbeat = *progOpts.heartbeat
	}
	if progOpts.healthCheckInterval != nil {
		healthCheckInterval = *progOpts.healthCheckInterval
	}
	if progOpts.deregisterCriticalServiceAfter != nil {
		deregisterCriticalServiceAfter = *progOpts.deregisterCriticalServiceAfter
	}

	// Append options to the final slice if they are meaningful.
	kratosOpts = append(kratosOpts, kratosconsul.WithHealthCheck(healthCheck))
	kratosOpts = append(kratosOpts, kratosconsul.WithHeartbeat(heartbeat))
	if healthCheckInterval > 0 {
		kratosOpts = append(kratosOpts, kratosconsul.WithHealthCheckInterval(healthCheckInterval))
	}
	if deregisterCriticalServiceAfter > 0 {
		kratosOpts = append(kratosOpts, kratosconsul.WithDeregisterCriticalServiceAfter(deregisterCriticalServiceAfter))
	}

	return kratosOpts
}

// NewDiscovery creates a new Consul discovery component.
func (f *factory) NewDiscovery(cfg *configv1.Discovery, opts ...registry.Option) (registry.KDiscovery, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client for discovery")
	}

	kratosOpts := buildKratosOptions(cfg, opts...)
	return kratosconsul.New(client, kratosOpts...), nil
}

// NewRegistrar creates a new Consul registrar component.
func (f *factory) NewRegistrar(cfg *configv1.Discovery, opts ...registry.Option) (registry.KRegistrar, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client for registrar")
	}

	kratosOpts := buildKratosOptions(cfg, opts...)
	return kratosconsul.New(client, kratosOpts...), nil
}
