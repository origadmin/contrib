/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package obj

import (
	"encoding/json"
	"reflect"

	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/encoding"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var _ config.Source = (*object)(nil)

type object struct {
	obj    any
	indent string
}

// NewSource new a object source.
func NewSource(obj any) config.Source {
	return &object{obj: obj}
}

func (o *object) Load() (kvs []*config.KeyValue, err error) {
	value, err := marshalObject(o.obj, o.indent)
	if err != nil {
		return nil, err
	}
	return []*config.KeyValue{value}, nil
}

func (o *object) Watch() (config.Watcher, error) {
	return NewWatcher()
}

func marshalObject(obj any, indent string) (*config.KeyValue, error) {
	if m, ok := obj.(proto.Message); ok {
		src, err := protojson.MarshalOptions{
			Indent:          indent,
			EmitUnpopulated: true,
		}.Marshal(m)
		if err != nil {
			return nil, err
		}
		return &config.KeyValue{
			Key:    reflect.TypeOf(m).String(),
			Format: "json",
			Value:  src,
		}, nil
	}
	src, err := json.MarshalIndent(obj, "", indent)
	if err != nil {
		return nil, err
	}
	return &config.KeyValue{
		Key:    reflect.TypeOf(obj).String(),
		Format: "json",
		Value:  src,
	}, nil
}

func unmarshalToKeyValue(codec encoding.Codec, data []byte, obj any) (*config.KeyValue, error) {
	err := codec.Unmarshal(data, obj)
	if err != nil {
		return nil, err
	}
	return marshalObject(obj, " ")
}
