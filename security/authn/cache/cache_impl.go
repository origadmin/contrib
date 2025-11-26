/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package token provides token caching functionality for security module
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/goexts/generic/configure"

	cachev1 "github.com/origadmin/runtime/api/gen/go/config/data/cache/v1"
	"github.com/origadmin/runtime/data/storage/cache"
	"github.com/origadmin/runtime/data/storage/cache/memory"
	storageiface "github.com/origadmin/runtime/interfaces/storage"
)

const (
	AccessKey  = "security:token:access"
	RefreshKey = "security:token:refresh"
)

type StorageOption = func(*cacheStorage)

func WithCache(c storageiface.Cache) StorageOption {
	return func(o *cacheStorage) {
		o.c = c
	}
}

// cacheStorage is the implementation of Cache interface
type cacheStorage struct {
	c storageiface.Cache
}

func (obj *cacheStorage) Store(ctx context.Context, tokenStr string, duration time.Duration) error {
	return obj.c.Set(ctx, tokenStr, "", duration)
}

func (obj *cacheStorage) Exist(ctx context.Context, tokenStr string) (bool, error) {
	ok, err := obj.c.Exists(ctx, tokenStr)
	switch {
	case ok:
		return true, nil
	default:
		return false, err
	}
}

func (obj *cacheStorage) Remove(ctx context.Context, tokenStr string) error {
	return obj.c.Delete(ctx, tokenStr)
}

func (obj *cacheStorage) Close(ctx context.Context) error {
	return obj.c.Close(ctx)
}

// New creates a new Cache instance
func New(ss ...StorageOption) Cache { // Use securityToken.Cache
	service := configure.New[cacheStorage](ss)
	if service.c == nil {
		defaultCacheConfig := &cachev1.CacheConfig{
			Driver: cache.DefaultDriver,
			Memory: &cachev1.MemoryConfig{
				Size:            memory.DefaultSize,
				Capacity:        memory.DefaultCapacity,
				Expiration:      memory.DefaultExpiration,
				CleanupInterval: memory.DefaultCleanupInterval,
			},
		}
		c, err := cache.New(defaultCacheConfig)
		if err != nil {
			// Handle error, perhaps log it or panic if cache is critical
			panic(fmt.Sprintf("failed to create default memory cache: %v", err))
		}
		service.c = c
	}
	return service
}
