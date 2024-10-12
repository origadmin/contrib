package config

import (
	"strings"

	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"

	"github.com/origadmin/toolkits/codec"
	"github.com/origadmin/toolkits/errors"
)

type source struct {
	source config.Source
}

func (s *source) Load() ([]*config.KeyValue, error) {
	return s.source.Load()
}

func (s *source) Watch() (config.Watcher, error) {
	return s.source.Watch()
}

func NewSource(path string) config.Source {
	return &source{
		source: file.NewSource(path),
	}
}

func SourceDecoder(src *config.KeyValue, target map[string]interface{}) error {
	if src.Format == "" {
		// expand key "aaa.bbb" into map[aaa]map[bbb]interface{}
		keys := strings.Split(src.Key, ".")
		for i, k := range keys {
			if i == len(keys)-1 {
				target[k] = src.Value
			} else {
				sub := make(map[string]interface{})
				target[k] = sub
				target = sub
			}
		}
		return nil
	}
	if codec := codec.TypeFromString(src.Format); codec.IsSupported() {
		return codec.Unmarshal(src.Value, &target)
	}
	return errors.Errorf("unsupported key: %s format: %s", src.Key, src.Format)
}

var _ config.Source = (*source)(nil)
