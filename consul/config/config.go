package config

import (
	"github.com/goexts/generic/settings"
	"github.com/hashicorp/consul/api"

	"github.com/origadmin/toolkits/errors"
	"github.com/origadmin/toolkits/runtime"
	"github.com/origadmin/toolkits/runtime/config"
	configv1 "github.com/origadmin/toolkits/runtime/gen/go/config/v1"
)

func init() {
	runtime.RegisterConfigFunc("consul", NewConsulConfig)
}

// NewConsulConfig create a new consul config.
func NewConsulConfig(ccfg *configv1.SourceConfig, ss ...config.SourceFunc) (config.Config, error) {
	cfg := api.DefaultConfig()
	cfg.Address = ccfg.Consul.Address
	cfg.Scheme = ccfg.Consul.Scheme

	apiClient, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	source, err := New(apiClient, WithPath(ccfg.Consul.Path))
	if err != nil {
		return nil, errors.Wrap(err, "consul source error")
	}
	option := settings.Apply(&config.SourceOption{
		Options: []config.Option{config.WithSource(source)},
	}, ss)
	return config.New(option.Options...), nil
}
