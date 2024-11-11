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

func optsFromConfig(ccfg *config.RegistryConfig_Consul) []Option {
	var opts []Option

	if ccfg.HealthCheck {
		opts = append(opts, WithHealthCheck(ccfg.HealthCheck))
	}
	if ccfg.HeartBeat {
		opts = append(opts, WithHeartbeat(ccfg.HeartBeat))
	}
	if ccfg.Timeout != nil {
		opts = append(opts, WithTimeout(ccfg.Timeout.AsDuration()))
	}
	if ccfg.Datacenter != "" {
		opts = append(opts, WithDatacenter(Datacenter(ccfg.Datacenter)))
	}
	if ccfg.HealthCheckInterval > 0 {
		opts = append(opts, WithHealthCheckInterval(int(ccfg.HealthCheckInterval)))
	}
	if ccfg.DeregisterCriticalServiceAfter > 0 {
		opts = append(opts, WithDeregisterCriticalServiceAfter(int(ccfg.DeregisterCriticalServiceAfter)))
	}
	//if true {
	//	consul.WithServiceResolver(func(ctx context.Context, entries []*api.ServiceEntry) []*registry.ServiceInstance {
	//		return []*registry.ServiceInstance{}
	//	})
	//	consul.WithServiceCheck()
	//}
	return opts
}

func (c *consulBuilder) NewDiscovery(cfg *config.RegistryConfig) (registry.Discovery, error) {
	if cfg == nil || cfg.Consul == nil {
		return nil, errors.New("configuration: consul config is required")
	}
	config := FromConfig(cfg.Consul)
	apiClient, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client")
	}
	r := New(apiClient, optsFromConfig(cfg.Consul)...)
	return r, nil
}

func (c *consulBuilder) NewRegistrar(cfg *config.RegistryConfig) (registry.Registrar, error) {
	if cfg == nil || cfg.Consul == nil {
		return nil, errors.New("configuration: consul config is required")
	}
	config := FromConfig(cfg.Consul)
	apiClient, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client")
	}
	r := New(apiClient, optsFromConfig(cfg.Consul)...)
	return r, nil
}

func FromConfig(cfg *config.RegistryConfig_Consul) *api.Config {
	apiconfig := api.DefaultConfig()
	if cfg.Address != "" {
		apiconfig.Address = cfg.Address
	}
	if cfg.Scheme != "" {
		apiconfig.Scheme = cfg.Scheme
	}
	if cfg.Datacenter != "" {
		apiconfig.Datacenter = cfg.Datacenter
	}
	//if cfg.PathPrefix != "" {
	//	apiconfig.PathPrefix = cfg.PathPrefix
	//}
	//if cfg.WaitTime != 0 {
	//	apiconfig.WaitTime = cfg.WaitTime
	//}
	if cfg.Token != "" {
		apiconfig.Token = cfg.Token
	}
	//if cfg.TokenFile != "" {
	//	apiconfig.Token = cfg.TokenFile
	//}
	//if cfg.Namespace != "" {
	//	apiconfig.Namespace = cfg.Namespace
	//}
	//if cfg.Partition != "" {
	//	apiconfig.Partition = cfg.Partition
	//}
	//apiconfig.TLSConfig = api.TLSConfig{
	//	Address:            cfg.TLSConfig.Address,
	//	CAFile:             cfg.TLSConfig.CAFile,
	//	CAPath:             cfg.TLSConfig.CAPath,
	//	CAPem:              cfg.TLSConfig.CAPem,
	//	CertFile:           cfg.TLSConfig.CertFile,
	//	CertPEM:            cfg.TLSConfig.CertPEM,
	//	KeyFile:            cfg.TLSConfig.KeyFile,
	//	KeyPEM:             cfg.TLSConfig.KeyPEM,
	//	InsecureSkipVerify: cfg.TLSConfig.InsecureSkipVerify,
	//}
	return apiconfig
}
