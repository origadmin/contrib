package config

import (
	"github.com/go-kratos/kratos/contrib/config/consul/v2"
	"github.com/hashicorp/consul/api"

	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/runtime/config"
	"github.com/origadmin/toolkits/runtime/kratos"
)

func init() {
	kratos.RegistryConfig("consul", NewConsulConfig)
}

func NewConsulConfig(ccfg *config.SourceConfig, opts ...config.Option) (config.Config, error) {
	cfg := api.DefaultConfig()
	cfg.Address = ccfg.Consul.Address
	cfg.Scheme = ccfg.Consul.Scheme

	cli, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	source, err := consul.New(cli,
		consul.WithPath(ccfg.Consul.Path),
	)
	if err != nil {
		return nil, errors.Wrap(err, "consul source error")
	}
	opts = append(opts, config.WithSource(source))
	return config.New(opts...), nil
}
