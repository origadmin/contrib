package registry

import (
	"github.com/hashicorp/consul/api"

	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/runtime"
	"github.com/origadmin/toolkits/runtime/config"
	"github.com/origadmin/toolkits/runtime/registry"
)

type consulBuilder struct {
}

func init() {
	runtime.RegisterRegistry("consul", &consulBuilder{})
}

func optsFromConfig(registry *config.Registry) []Option {
	var opts []Option

	cfg := registry.GetConsul()
	if cfg == nil {
		return opts
	}

	if cfg.HealthCheck {
		opts = append(opts, WithHealthCheck(cfg.HealthCheck))
	}
	if cfg.HeartBeat {
		opts = append(opts, WithHeartbeat(cfg.HeartBeat))
	}
	if cfg.Timeout != nil {
		opts = append(opts, WithTimeout(cfg.Timeout.AsDuration()))
	}
	if cfg.Datacenter != "" {
		opts = append(opts, WithDatacenter(Datacenter(cfg.Datacenter)))
	}
	if cfg.HealthCheckInterval > 0 {
		opts = append(opts, WithHealthCheckInterval(int(cfg.HealthCheckInterval)))
	}
	if cfg.DeregisterCriticalServiceAfter > 0 {
		opts = append(opts, WithDeregisterCriticalServiceAfter(int(cfg.DeregisterCriticalServiceAfter)))
	}
	return opts
}

func (c *consulBuilder) NewDiscovery(cfg *config.Registry) (registry.Discovery, error) {
	if cfg == nil || cfg.Consul == nil {
		return nil, errors.New("configuration: consul config is required")
	}
	config := fromConfig(cfg)
	apiClient, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client")
	}
	r := New(apiClient, optsFromConfig(cfg)...)
	return r, nil
}

func (c *consulBuilder) NewRegistrar(cfg *config.Registry) (registry.Registrar, error) {
	if cfg == nil || cfg.Consul == nil {
		return nil, errors.New("configuration: consul config is required")
	}
	config := fromConfig(cfg)
	apiClient, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client")
	}
	r := New(apiClient, optsFromConfig(cfg)...)
	return r, nil
}

func fromConfig(registry *config.Registry) *api.Config {
	apiconfig := api.DefaultConfig()
	cfg := registry.GetConsul()
	if cfg == nil {
		return apiconfig
	}
	if cfg.Address != "" {
		apiconfig.Address = cfg.Address
	}
	if cfg.Scheme != "" {
		apiconfig.Scheme = cfg.Scheme
	}
	if cfg.Datacenter != "" {
		apiconfig.Datacenter = cfg.Datacenter
	}
	if cfg.Token != "" {
		apiconfig.Token = cfg.Token
	}
	return apiconfig
}
