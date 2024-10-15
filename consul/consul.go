package consul

import (
	"github.com/go-kratos/kratos/contrib/registry/consul/v2"
	registryv2 "github.com/go-kratos/kratos/v2/registry"
	"github.com/hashicorp/consul/api"
)

type consulBuilder struct {
}

func (c *consulBuilder) NewClient(conf registry.Config) (registryv2.Discovery, error) {
	config := FromConfig(conf)
	consulCli, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	r := consul.New(consulCli)
	return r, nil
}

func (c *consulBuilder) NewServer(conf registry.Config) (registryv2.Registrar, error) {
	config := FromConfig(conf)
	consulCli, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	r := consul.New(consulCli)
	return r, nil
}

func FromConfig(config registry.Config) *api.Config {
	if config.Type != "consul" {
		panic("consul config type error")
	}
	consulConfig := config.Consul
	apiconfig := api.DefaultConfig()
	if consulConfig.Address != "" {
		apiconfig.Address = consulConfig.Address
	}
	if consulConfig.Scheme != "" {
		apiconfig.Scheme = consulConfig.Scheme
	}
	if consulConfig.Datacenter != "" {
		apiconfig.Datacenter = consulConfig.Datacenter
	}
	if consulConfig.PathPrefix != "" {
		apiconfig.PathPrefix = consulConfig.PathPrefix
	}
	if consulConfig.WaitTime != 0 {
		apiconfig.WaitTime = consulConfig.WaitTime
	}
	if consulConfig.Token != "" {
		apiconfig.Token = consulConfig.Token
	}
	if consulConfig.TokenFile != "" {
		apiconfig.Token = consulConfig.TokenFile
	}
	if consulConfig.Namespace != "" {
		apiconfig.Namespace = consulConfig.Namespace
	}
	if consulConfig.Partition != "" {
		apiconfig.Partition = consulConfig.Partition
	}
	apiconfig.TLSConfig = api.TLSConfig{
		Address:            consulConfig.TLSConfig.Address,
		CAFile:             consulConfig.TLSConfig.CAFile,
		CAPath:             consulConfig.TLSConfig.CAPath,
		CAPem:              consulConfig.TLSConfig.CAPem,
		CertFile:           consulConfig.TLSConfig.CertFile,
		CertPEM:            consulConfig.TLSConfig.CertPEM,
		KeyFile:            consulConfig.TLSConfig.KeyFile,
		KeyPEM:             consulConfig.TLSConfig.KeyPEM,
		InsecureSkipVerify: consulConfig.TLSConfig.InsecureSkipVerify,
	}
	return apiconfig
	//return &api.Config{
	//	Address:    consulConfig.Address,
	//	Scheme:     consulConfig.Scheme,
	//	PathPrefix: consulConfig.PathPrefix,
	//	Datacenter: consulConfig.Datacenter,
	//	Transport:  consulConfig.Transport,
	//	HttpClient: consulConfig.HttpClient,
	//	WaitTime:   consulConfig.WaitTime,
	//	Token:      consulConfig.Token,
	//	TokenFile:  consulConfig.TokenFile,
	//	Namespace:  consulConfig.Namespace,
	//	Partition:  consulConfig.Partition,
	//}
}

func init() {
	registry.Register("consul", &consulBuilder{})
}
