/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package memory implements the functions, types, and interfaces for the module.
package memory

import (
	"context"
	"time"

	"github.com/coocood/freecache"
	"github.com/goexts/generic/types"
	configv1 "github.com/origadmin/runtime/gen/go/config/v1"
	"github.com/origadmin/toolkits/errors"
)

const (
	defaultSize = 64 * 1024 * 1024
)

const (
	ErrNotFound = errors.String("not found")
)

type Cache struct {
	Expiration      time.Duration
	CleanupInterval time.Duration
	Cache           *freecache.Cache
}

func (obj *Cache) Set(ctx context.Context, key, value string, expiration ...time.Duration) error {
	var exp time.Duration
	if len(expiration) > 0 {
		exp = expiration[0]
	}
	return obj.Cache.Set([]byte(key), []byte(value), int(exp))
}

func (obj *Cache) Get(ctx context.Context, key string) (string, error) {
	val, err := obj.Cache.Get([]byte(key))
	if err != nil {
		return "", ErrNotFound
	}
	return string(val), nil
}

func (obj *Cache) Exists(ctx context.Context, key string) error {
	_, err := obj.Cache.Get([]byte(key))
	if err != nil {
		return ErrNotFound
	}
	return nil
}

func (obj *Cache) Delete(ctx context.Context, key string) error {
	affected := obj.Cache.Del([]byte(key))
	if !affected {
		return ErrNotFound
	}
	return nil
}

func (obj *Cache) GetAndDelete(ctx context.Context, key string) (string, error) {
	value, err := obj.Get(ctx, key)
	if err != nil {
		return "", err
	}
	err = obj.Delete(ctx, key)
	if err != nil {
		return "", err
	}
	return value, nil
}

func (obj *Cache) Iterator(ctx context.Context, fn func(ctx context.Context, key, value string) bool) error {
	iter := obj.Cache.NewIterator()
	for entry := iter.Next(); entry != nil; entry = iter.Next() {
		if !fn(ctx, string(entry.Key), string(entry.Value)) {
			break
		}
	}
	return nil
}

func (obj *Cache) Close(_ context.Context) error {
	obj.Cache.Clear()
	return nil
}

func NewCache(data *configv1.Data) *Cache {
	cfg := data.GetCache().GetMemory()
	if cfg == nil {
		cfg = new(configv1.Data_Memory)
	}
	expiration := types.ZeroOr(cfg.GetExpiration().AsDuration(), 24*time.Hour)
	interval := types.ZeroOr(cfg.GetCleanupInterval().AsDuration(), 30*time.Minute)
	return &Cache{
		Expiration:      expiration,
		CleanupInterval: interval,
		Cache:           newFreeCache(defaultSize),
	}
}

func newFreeCache(size int) *freecache.Cache {
	return freecache.NewCache(size)
}
