package registry

import (
	"github.com/go-kratos/kratos/contrib/registry/consul/v2"
	registryv2 "github.com/go-kratos/kratos/v2/registry"
	"github.com/hashicorp/consul/api"

	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/runtime/config"
	"github.com/origadmin/toolkits/runtime/kratos"
)

type consulBuilder struct {
}

func init() {
	kratos.RegistryRegistry("consul", &consulBuilder{})
}

func optionsFromConfig(ccfg *config.RegistryConfig_Consul) []consul.Option {
	var opts []consul.Option

	if ccfg.HealthCheck {
		opts = append(opts, consul.WithHealthCheck(ccfg.HealthCheck))
	}
	if ccfg.HeartBeat {
		opts = append(opts, consul.WithHeartbeat(ccfg.HeartBeat))
	}
	if ccfg.Timeout != nil {
		opts = append(opts, consul.WithTimeout(ccfg.Timeout.AsDuration()))
	}
	if ccfg.Datacenter != "" {
		opts = append(opts, consul.WithDatacenter(consul.Datacenter(ccfg.Datacenter)))
	}
	if ccfg.HealthCheckInterval > 0 {
		opts = append(opts, consul.WithHealthCheckInterval(int(ccfg.HealthCheckInterval)))
	}
	if ccfg.DeregisterCriticalServiceAfter > 0 {
		opts = append(opts, consul.WithDeregisterCriticalServiceAfter(int(ccfg.DeregisterCriticalServiceAfter)))
	}
	//if true {
	//	consul.WithServiceResolver(func(ctx context.Context, entries []*api.ServiceEntry) []*registryv2.ServiceInstance {
	//		return []*registryv2.ServiceInstance{}
	//	})
	//	consul.WithServiceCheck()
	//}
	return opts
}

func (c *consulBuilder) NewDiscovery(cfg *config.RegistryConfig) (registryv2.Discovery, error) {
	if cfg == nil || cfg.Consul == nil {
		return nil, errors.New("configuration: consul config is required")
	}
	config := FromConfig(cfg.Consul)
	consulCli, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client")
	}
	opts := optionsFromConfig(cfg.Consul)
	r := consul.New(consulCli, opts...)
	return r, nil
}

func (c *consulBuilder) NewRegistrar(cfg *config.RegistryConfig) (registryv2.Registrar, error) {
	if cfg == nil || cfg.Consul == nil {
		return nil, errors.New("configuration: consul config is required")
	}
	config := FromConfig(cfg.Consul)
	consulCli, err := api.NewClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create consul client")
	}
	opts := optionsFromConfig(cfg.Consul)
	r := consul.New(consulCli, opts...)
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
