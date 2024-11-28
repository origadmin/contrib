/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package config

import (
	"encoding/json"

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
	runtime.RegisterConfigFunc("consul", NewConsulConfig)
	runtime.RegisterConfigSync("consul", SyncConfig)
}

// NewConsulConfig create a new consul config.
func NewConsulConfig(ccfg *configv1.SourceConfig, ss ...config.SourceSetting) (config.Config, error) {
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

	option := settings.Apply(&config.SourceOption{}, ss)
	option.Options = append(option.Options, config.WithSource(source))
	if option.Decoder != nil {
		option.Options = append(option.Options, config.WithDecoder(option.Decoder))
	}
	return config.New(option.Options...), nil
}

func SyncConfig(ccfg *configv1.SourceConfig, v any, ss ...config.SourceSetting) error {
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

	option := settings.Apply(&config.SourceOption{}, ss)
	encode := marshalValue
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

func marshalValue(v any) ([]byte, error) {
	if data, ok := v.(proto.Message); ok {
		opt := protojson.MarshalOptions{
			EmitUnpopulated: true,
			Indent:          " ",
		}
		return opt.Marshal(data)
	}
	return json.Marshal(v)
}

func FileConfigPath(serviceName, filename string) string {
	return "/config/" + serviceName + "/" + filename
}
