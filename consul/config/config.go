/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package config

import (
	"encoding/json"

	"github.com/go-kratos/kratos/v2/config/env"
	"github.com/goexts/generic/settings"
	"github.com/hashicorp/consul/api"
	"github.com/origadmin/toolkits/errors"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/origadmin/runtime"
	"github.com/origadmin/runtime/config"
	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
)

func init() {
	runtime.RegisterConfigFunc(Type, NewConsulConfig)
	runtime.RegisterConfigSync(Type, SyncConfig)
}

// NewConsulConfig create a new consul config.
func NewConsulConfig(ccfg *configv1.SourceConfig, ss ...config.Option) (config.KConfig, error) {
	consul := ccfg.GetConsul()
	if consul == nil {
		return nil, errors.New("consul config error")
	}

	cfg := api.DefaultConfig()
	cfg.Address = consul.Address
	cfg.Scheme = consul.Scheme

	apiClient, err := api.NewClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "consul client error")
	}

	if consul.Path == "" {
		consul.Path = FileConfigPath(ccfg.Name, DefaultPathName)
	}

	source, err := New(apiClient, WithPath(consul.Path))
	if err != nil {
		return nil, errors.Wrap(err, "consul source error")
	}

	option := settings.ApplyOrZero(ss...)
	var configSources = []config.KSource{source}
	if ccfg.EnvPrefixes != nil {
		configSources = append(configSources, env.NewSource(ccfg.EnvPrefixes...))
	}
	option.SourceOptions = append(option.SourceOptions, config.WithSource(configSources...))
	if option.Decoder != nil {
		option.SourceOptions = append(option.SourceOptions, config.WithDecoder(option.Decoder))
	}
	return config.NewSourceConfig(option.SourceOptions...), nil
}

func SyncConfig(ccfg *configv1.SourceConfig, v any, ss ...config.Option) error {
	consul := ccfg.GetConsul()
	if consul == nil {
		return errors.New("consul config error")
	}

	cfg := api.DefaultConfig()
	cfg.Address = consul.Address
	cfg.Scheme = consul.Scheme
	apiClient, err := api.NewClient(cfg)
	if err != nil {
		return errors.Wrap(err, "consul client error")
	}

	if consul.Path == "" {
		consul.Path = FileConfigPath(ccfg.Name, DefaultPathName)
	}

	encode := marshalJSON
	option := settings.ApplyOrZero(ss...)
	if option.Encoder != nil {
		encode = option.Encoder
	}
	marshal, err := encode(v)
	if err != nil {
		return errors.Wrap(err, "marshal config error")
	}

	if _, err := apiClient.KV().Put(&api.KVPair{
		Key:   consul.Path,
		Value: marshal,
	}, nil); err != nil {
		return errors.Wrap(err, "consul put error")
	}
	return nil
}

func FileConfigPath(serviceName, filename string) string {
	return "/config/" + serviceName + "/" + filename
}
func marshalJSON(v any) ([]byte, error) {
	if data, ok := v.(proto.Message); ok {
		opt := protojson.MarshalOptions{
			EmitUnpopulated: true,
			Indent:          " ",
		}
		return opt.Marshal(data)
	}
	return json.Marshal(v)
}
