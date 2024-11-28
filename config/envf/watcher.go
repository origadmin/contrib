/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

package envf

import (
	"context"

	"github.com/go-kratos/kratos/v2/config"
)

var _ config.Watcher = (*watcher)(nil)

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