// Package etcd implements the functions, types, and interfaces for the module.
package etcd

import (
	"github.com/go-kratos/kratos/contrib/registry/etcd/v2"
	etcdclient "go.etcd.io/etcd/client/v3"

	discoveryv1 "github.com/origadmin/runtime/api/gen/go/config/discovery/v1"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/runtime/registry"
	"github.com/origadmin/toolkits/errors"
)

type factory struct {
}

func init() {
	registry.Register(Type, &factory{})
}

func (c *factory) NewDiscovery(cfg *discoveryv1.Discovery, opts ...options.Option) (registry.KDiscovery, error) {
	if cfg.GetEtcd() == nil {
		return nil, errors.New("etcd config is nil")
	}
	config := fromConfig(cfg.GetEtcd())
	etcdCli, err := etcdclient.New(config)
	if err != nil {
		return nil, err
	}
	r := etcd.New(etcdCli)
	return r, nil
}

func (c *factory) NewRegistrar(cfg *discoveryv1.Discovery, opts ...options.Option) (registry.KRegistrar, error) {
	if cfg.GetEtcd() == nil {
		return nil, errors.New("etcd config is nil")
	}
	config := fromConfig(cfg.GetEtcd())
	etcdCli, err := etcdclient.New(config)
	if err != nil {
		return nil, err
	}
	r := etcd.New(etcdCli)
	return r, nil
}

func fromConfig(etcdConfig *discoveryv1.ETCD) etcdclient.Config {
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
