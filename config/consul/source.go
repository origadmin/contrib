/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package consul

import (
	"encoding/json"

	kratosconfig "github.com/go-kratos/kratos/v2/config"
	"github.com/hashicorp/consul/api"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/origadmin/runtime/config"
	"github.com/origadmin/runtime/interfaces/options"
	"github.com/origadmin/toolkits/errors"

	sourcev1 "github.com/origadmin/runtime/api/gen/go/config/source/v1"
)

func init() {
	config.RegisterSourceFactory(Type, config.SourceFunc(NewSource))
}

// NewSource create a new consul config.
func NewSource(srcConfig *sourcev1.SourceConfig, opts ...options.Option) (kratosconfig.Source, error) {
	consulConfig := srcConfig.GetConsul()
	if consulConfig == nil {
		return nil, errors.New("consul config error")
	}

	cfg := api.DefaultConfig()
	cfg.Address = consulConfig.Address
	cfg.Scheme = consulConfig.Scheme

	apiClient, err := api.NewClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "consul client error")
	}

	o := FromOptions(opts)

	source, err := New(apiClient, o.Options...)
	if err != nil {
		return nil, errors.Wrap(err, "consul source error")
	}

	return source, nil
}

func SyncConfig(ccfg *sourcev1.SourceConfig, v any, opts ...options.Option) error {
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
