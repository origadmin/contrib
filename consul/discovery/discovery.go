package discovery

import (
	registryv2 "github.com/go-kratos/kratos/v2/registry"

	"github.com/origadmin/toolkits/runtime/kratos"
)

type consulBuilder struct {
}

//func (c *consulBuilder) NewClient(conf discovery.Config) (registryv2.Discovery, error) {
//	config := FromConfig(conf)
//	consulCli, err := api.NewClient(config)
//	if err != nil {
//		return nil, err
//	}
//	r := consul.New(consulCli)
//	return r, nil
//}
//
//func (c *consulBuilder) NewServer(conf discovery.Config) (registryv2.Registrar, error) {
//	config := FromConfig(conf)
//	consulCli, err := api.NewClient(config)
//	if err != nil {
//		return nil, err
//	}
//	r := consul.New(consulCli)
//	return r, nil
//}
//
//func FromConfig(config discovery.Config) *api.Config {
//	if config.Type != "consul" {
//		panic("consul config type error")
//	}
//	consulConfig := config.Consul
//	apiconfig := api.DefaultConfig()
//	if consulConfig.Address != "" {
//		apiconfig.Address = consulConfig.Address
//	}
//	if consulConfig.Scheme != "" {
//		apiconfig.Scheme = consulConfig.Scheme
//	}
//	if consulConfig.Datacenter != "" {
//		apiconfig.Datacenter = consulConfig.Datacenter
//	}
//	if consulConfig.PathPrefix != "" {
//		apiconfig.PathPrefix = consulConfig.PathPrefix
//	}
//	if consulConfig.WaitTime != 0 {
//		apiconfig.WaitTime = consulConfig.WaitTime
//	}
//	if consulConfig.Token != "" {
//		apiconfig.Token = consulConfig.Token
//	}
//	if consulConfig.TokenFile != "" {
//		apiconfig.Token = consulConfig.TokenFile
//	}
//	if consulConfig.Namespace != "" {
//		apiconfig.Namespace = consulConfig.Namespace
//	}
//	if consulConfig.Partition != "" {
//		apiconfig.Partition = consulConfig.Partition
//	}
//	apiconfig.TLSConfig = api.TLSConfig{
//		Address:            consulConfig.TLSConfig.Address,
//		CAFile:             consulConfig.TLSConfig.CAFile,
//		CAPath:             consulConfig.TLSConfig.CAPath,
//		CAPem:              consulConfig.TLSConfig.CAPem,
//		CertFile:           consulConfig.TLSConfig.CertFile,
//		CertPEM:            consulConfig.TLSConfig.CertPEM,
//		KeyFile:            consulConfig.TLSConfig.KeyFile,
//		KeyPEM:             consulConfig.TLSConfig.KeyPEM,
//		InsecureSkipVerify: consulConfig.TLSConfig.InsecureSkipVerify,
//	}
//	return apiconfig
//}

func init() {
	kratos.RegistryDiscovery("consul", func(a any) (registryv2.Discovery, error) {
		panic("not implemented")
	})
}
