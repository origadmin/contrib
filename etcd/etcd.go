package etcd

import (
	"github.com/go-kratos/kratos/contrib/registry/etcd/v2"
	registryv2 "github.com/go-kratos/kratos/v2/registry"
	etcdclient "go.etcd.io/etcd/client/v3"

	"github.com/origadmin/toolkits/runtime"
	"github.com/origadmin/toolkits/runtime/config"
)

type etcdBuilder struct {
}

func init() {
	runtime.RegisterRegistry("etcd", &etcdBuilder{})
}

func (c *etcdBuilder) NewDiscovery(cfg *config.RegistryConfig) (registryv2.Discovery, error) {
	config := FromConfig(cfg)
	etcdCli, err := etcdclient.New(config)
	if err != nil {
		return nil, err
	}
	r := etcd.New(etcdCli)
	return r, nil
}

func (c *etcdBuilder) NewRegistrar(cfg *config.RegistryConfig) (registryv2.Registrar, error) {
	config := FromConfig(cfg)
	etcdCli, err := etcdclient.New(config)
	if err != nil {
		return nil, err
	}
	r := etcd.New(etcdCli)
	return r, nil
}

func FromConfig(cfg *config.RegistryConfig) etcdclient.Config {
	if cfg.Type != "etcd" {
		panic("etcd config type error")
	}
	etcdConfig := cfg.Etcd
	apiconfig := etcdclient.Config{
		Endpoints: etcdConfig.Endpoints,
	}
	//if etcdConfig.DialTimeout != 0 {
	//	apiconfig.DialTimeout = etcdConfig.DialTimeout
	//}
	//if etcdConfig.DialKeepAliveTime != 0 {
	//	apiconfig.DialKeepAliveTime = etcdConfig.DialKeepAliveTime
	//}
	//if etcdConfig.DialKeepAliveTimeout != 0 {
	//	apiconfig.DialKeepAliveTimeout = etcdConfig.DialKeepAliveTimeout
	//}
	//if etcdConfig.MaxCallRecvMsgSize != 0 {
	//	apiconfig.MaxCallRecvMsgSize = etcdConfig.MaxCallRecvMsgSize
	//}
	//if etcdConfig.MaxCallSendMsgSize != 0 {
	//	apiconfig.MaxCallSendMsgSize = etcdConfig.MaxCallSendMsgSize
	//}
	//apiconfig.TLS = etcdConfig.TLS
	return apiconfig
}
