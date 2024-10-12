package envf

import (
	"os"
	"strings"

	"github.com/go-kratos/kratos/v2/config"

	"github.com/origadmin/toolkits/codec"
	"github.com/origadmin/toolkits/errors"
)

type envf struct {
	files    []string
	data     map[string]string
	prefixes []string
}

func NewSource(files []string, prefixes ...string) config.Source {
	return &envf{
		files:    files,
		prefixes: prefixes,
	}
}

func (e *envf) Load() (kv []*config.KeyValue, err error) {
	if len(e.files) > 0 {
		for _, f := range e.files {
			if _, err := os.Stat(f); err != nil {
				continue
			}
			if err := codec.DecodeFromFile(f, &e.data); err != nil {
				return nil, errors.Wrapf(err, "decode file %s error", f)
			}
		}
	}
	return e.load(e.data), nil
}

func (e *envf) load(envs map[string]string) []*config.KeyValue {
	var kv []*config.KeyValue
	for k, v := range envs {
		if len(e.prefixes) > 0 {
			p, ok := matchPrefix(e.prefixes, k)
			if !ok || len(p) == len(k) {
				continue
			}
			// trim prefix
			k = strings.TrimPrefix(k, p)
			k = strings.TrimPrefix(k, "_")
		}

		if len(k) != 0 {
			kv = append(kv, &config.KeyValue{
				Key:   k,
				Value: []byte(v),
			})
		}
	}
	return kv
}

func (e *envf) Watch() (config.Watcher, error) {
	w, err := NewWatcher()
	if err != nil {
		return nil, err
	}
	return w, nil
}

func matchPrefix(prefixes []string, s string) (string, bool) {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return p, true
		}
	}
	return "", false
}
