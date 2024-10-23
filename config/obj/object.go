package obj

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/encoding"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var _ config.Source = (*object)(nil)

type object struct {
	path string
	obj  any
}

// NewSource new a object source.
func NewSource(path string, obj any) config.Source {
	return &object{path: path, obj: obj}
}

func (o *object) loadFile(path string) (*config.KeyValue, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	codec := encoding.GetCodec(format(info.Name()))
	return unmarshalToKeyValue(codec, data, o.obj)
}

func (o *object) loadDir(path string) (kvs []*config.KeyValue, err error) {
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		// ignore hidden files
		if file.IsDir() || strings.HasPrefix(file.Name(), ".") {
			continue
		}
		kv, err := o.loadFile(filepath.Join(path, file.Name()))
		if err != nil {
			return nil, err
		}
		kvs = append(kvs, kv)
	}
	return
}

func (o *object) Load() (kvs []*config.KeyValue, err error) {
	fi, err := os.Stat(o.path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return o.loadDir(o.path)
	}
	kv, err := o.loadFile(o.path)
	if err != nil {
		return nil, err
	}
	return []*config.KeyValue{kv}, nil
}

func (o *object) Watch() (config.Watcher, error) {
	return NewWatcher()
}

func marshalObject(obj any) (*config.KeyValue, error) {
	if m, ok := obj.(proto.Message); ok {
		src, err := protojson.MarshalOptions{
			Indent:          " ",
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
	src, err := json.MarshalIndent(obj, "", " ")
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
	return marshalObject(obj)
}
