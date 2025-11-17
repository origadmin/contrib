/*
 * Copyright (c) 2024 OrigAdmin. All rights reserved.
 */

// Package token provides token caching functionality for security module
package token

import (
	"context"
	"fmt"
	"time"

	"github.com/goexts/generic/configure"

	storagev1 "github.com/origadmin/runtime/api/gen/go/config/data/cache/v1"
	"github.com/origadmin/runtime/data/storage/cache"
	securityToken "github.com/origadmin/contrib/security/token" // Updated import path
	storageiface "github.com/origadmin/runtime/interfaces/storage"
)

const (
	CacheAccess  = "security:token:access"
	CacheRefresh = "security:token:refresh"
)

type StorageOption = func(*tokenCacheStorage)

func WithCache(c storageiface.Cache) StorageOption {
	return func(o *tokenCacheStorage) {
		o.c = c
	}
}

// tokenCacheStorage is the implementation of CacheStorage interface
type tokenCacheStorage struct {
	c storageiface.Cache
}

func (obj *tokenCacheStorage) Store(ctx context.Context, tokenStr string, duration time.Duration) error {
	return obj.c.Set(ctx, tokenStr, "", duration)
}

func (obj *tokenCacheStorage) Exist(ctx context.Context, tokenStr string) (bool, error) {
	ok, err := obj.c.Exists(ctx, tokenStr)
	switch {
	case ok:
		return true, nil
	default:
		return false, err
	}
}

func (obj *tokenCacheStorage) Remove(ctx context.Context, tokenStr string) error {
	return obj.c.Delete(ctx, tokenStr)
}

func (obj *tokenCacheStorage) Close(ctx context.Context) error {
	return obj.c.Close(ctx)
}

// New creates a new CacheStorage instance
func New(ss ...StorageOption) securityToken.CacheStorage { // Use securityToken.CacheStorage
	service := configure.New[tokenCacheStorage](ss)
	if service.c == nil {
		defaultCacheConfig := &storagev1.CacheConfig{
			Driver: "memory",
			Memory: &storagev1.MemoryConfig{},
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
