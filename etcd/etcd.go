package etcd

import (
	"github.com/go-kratos/kratos/contrib/registry/etcd/v2"
	registryv2 "github.com/go-kratos/kratos/v2/registry"
	etcdclient "go.etcd.io/etcd/client/v3"
)

type etcdBuilder struct {
}

func (c *etcdBuilder) NewClient(conf registry.Config) (registryv2.Discovery, error) {
	config := FromConfig(conf)
	etcdCli, err := etcdclient.New(config)
	if err != nil {
		return nil, err
	}
	r := etcd.New(etcdCli)
	return r, nil
}

func (c *etcdBuilder) NewServer(conf registry.Config) (registryv2.Registrar, error) {
	config := FromConfig(conf)
	etcdCli, err := etcdclient.New(config)
	if err != nil {
		return nil, err
	}
	r := etcd.New(etcdCli)
	return r, nil
}

func FromConfig(config registry.Config) etcdclient.Config {
	if config.Type != "etcd" {
		panic("etcd config type error")
	}
	etcdConfig := config.ETCD
	apiconfig := etcdclient.Config{
		Endpoints: etcdConfig.Endpoints,
	}
	if etcdConfig.DialTimeout != 0 {
		apiconfig.DialTimeout = etcdConfig.DialTimeout
	}
	if etcdConfig.DialKeepAliveTime != 0 {
		apiconfig.DialKeepAliveTime = etcdConfig.DialKeepAliveTime
	}
	if etcdConfig.DialKeepAliveTimeout != 0 {
		apiconfig.DialKeepAliveTimeout = etcdConfig.DialKeepAliveTimeout
	}
	if etcdConfig.MaxCallRecvMsgSize != 0 {
		apiconfig.MaxCallRecvMsgSize = etcdConfig.MaxCallRecvMsgSize
	}
	if etcdConfig.MaxCallSendMsgSize != 0 {
		apiconfig.MaxCallSendMsgSize = etcdConfig.MaxCallSendMsgSize
	}
	apiconfig.TLS = etcdConfig.TLS
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
	registry.Register("consul", &etcdBuilder{})
}
