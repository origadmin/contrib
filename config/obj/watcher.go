package obj

import (
	"context"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/go-kratos/kratos/v2/config"
)

var _ config.Watcher = (*watcher)(nil)
var _ config.Watcher = (*fileWatcher)(nil)

type watcher struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewWatcher() (config.Watcher, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &watcher{ctx: ctx, cancel: cancel}, nil
}

// Next will be blocked until the Stop method is called
func (w *watcher) Next() ([]*config.KeyValue, error) {
	<-w.ctx.Done()
	return nil, w.ctx.Err()
}

func (w *watcher) Stop() error {
	w.cancel()
	return nil
}

type fileWatcher struct {
	f  *object
	fw *fsnotify.Watcher

	ctx    context.Context
	cancel context.CancelFunc
}

func newWatcher(f *object) (config.Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := fw.Add(f.path); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &fileWatcher{f: f, fw: fw, ctx: ctx, cancel: cancel}, nil
}

func (w *fileWatcher) Next() ([]*config.KeyValue, error) {
	select {
	case <-w.ctx.Done():
		return nil, w.ctx.Err()
	case event := <-w.fw.Events:
		if event.Op == fsnotify.Rename {
			if _, err := os.Stat(event.Name); err == nil || os.IsExist(err) {
				if err := w.fw.Add(event.Name); err != nil {
					return nil, err
				}
			}
		}
		fi, err := os.Stat(w.f.path)
		if err != nil {
			return nil, err
		}
		path := w.f.path
		if fi.IsDir() {
			path = filepath.Join(w.f.path, filepath.Base(event.Name))
		}
		kv, err := w.f.loadFile(path)
		if err != nil {
			return nil, err
		}
		return []*config.KeyValue{kv}, nil
	case err := <-w.fw.Errors:
		return nil, err
	}
}

func (w *fileWatcher) Stop() error {
	w.cancel()
	return w.fw.Close()
}
