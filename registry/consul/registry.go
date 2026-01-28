/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package consul

import (
	kratosconsul "github.com/go-kratos/kratos/contrib/registry/consul/v2"
	"github.com/hashicorp/consul/api"

	discoveryv1 "github.com/origadmin/runtime/api/gen/go/config/discovery/v1"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/registry"
	"github.com/origadmin/toolkits/errors"
)

// factory implements the registry.Factory interface for Consul.
type factory struct{}

func init() {
	// The const 'Type' is defined in 'consul.go' as `const Type = "consul"`.
	discovery.Register(Type, &factory{})
}

// newClient creates a new Consul API client from the given configuration.
func newClient(cfg *discoveryv1.Discovery) (*api.Client, error) {
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
func buildKratosOptions(consulCfg *discoveryv1.Consul, opts ...options.Option) []kratosconsul.Option {
	// Apply programmatic options to a registry.Options struct to populate the context.
	progOpts := fromOptions(opts)

	var kratosOpts []kratosconsul.Option

	// Determine final values, with programmatic options taking precedence over config files.
	var (
		healthCheck                    bool
		heartbeat                      bool
		healthCheckInterval            int
		deregisterCriticalServiceAfter int
	)

	if consulCfg != nil {
		if consulCfg.HealthCheck {
			healthCheck = consulCfg.HealthCheck
		}
		if consulCfg.HeartBeat {
			heartbeat = consulCfg.HeartBeat
		}
		if consulCfg.GetHealthCheckInterval() > 0 {
			healthCheckInterval = int(consulCfg.GetHealthCheckInterval())
		}
		if consulCfg.GetDeregisterCriticalServiceAfter() > 0 {
			deregisterCriticalServiceAfter = int(consulCfg.GetDeregisterCriticalServiceAfter())
		}
	}

	//if progOpts.healthCheck {
	//	healthCheck = progOpts.healthCheck
	//}
	//if progOpts.heartbeat {
	//	heartbeat = progOpts.heartbeat
	//}
	//if progOpts.healthCheckInterval > 0 {
	//	healthCheckInterval = progOpts.healthCheckInterval
	//}
	//if progOpts.deregisterCriticalServiceAfter > 0 {
	//	deregisterCriticalServiceAfter = progOpts.deregisterCriticalServiceAfter
	//}

	kratosOpts = append(kratosOpts, kratosconsul.WithHealthCheck(healthCheck))
	kratosOpts = append(kratosOpts, kratosconsul.WithHeartbeat(heartbeat))
	if healthCheckInterval > 0 {
		kratosOpts = append(kratosOpts, kratosconsul.WithHealthCheckInterval(healthCheckInterval))
	}
	if deregisterCriticalServiceAfter > 0 {
		kratosOpts = append(kratosOpts, kratosconsul.WithDeregisterCriticalServiceAfter(deregisterCriticalServiceAfter))
	}

	return append(kratosOpts, progOpts.Options...)
}

// NewDiscovery creates a new Consul discovery component.
func (f *factory) NewDiscovery(cfg *discoveryv1.Discovery, opts ...options.Option) (discovery.KDiscovery, error) {
	if cfg.GetConsul() == nil {
		return nil, errors.New("discovery configuration is missing")
	}
	client, err := newClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client for discovery")
	}

	kratosOpts := buildKratosOptions(cfg.GetConsul(), opts...)
	return kratosconsul.New(client, kratosOpts...), nil
}

// NewRegistrar creates a new Consul registrar component.
func (f *factory) NewRegistrar(cfg *discoveryv1.Discovery, opts ...options.Option) (discovery.KRegistrar, error) {
	if cfg.GetConsul() == nil {
		return nil, errors.New("discovery configuration is missing")
	}
	client, err := newClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client for registrar")
	}

	kratosOpts := buildKratosOptions(cfg.GetConsul(), opts...)
	return kratosconsul.New(client, kratosOpts...), nil
}
