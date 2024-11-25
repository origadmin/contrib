package memory

import (
	"context"
	"time"

	"github.com/coocood/freecache"
	"github.com/goexts/generic/types"

	"github.com/origadmin/toolkits/errors"

	configv1 "github.com/origadmin/toolkits/runtime/gen/go/config/v1"
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

func NewCache(cfg *configv1.Data_Memory) *Cache {
	if cfg == nil {
		cfg = new(configv1.Data_Memory)
	}
	return &Cache{
		Expiration:      types.ZeroOr(cfg.GetExpiration().AsDuration(), 24*time.Hour),
		CleanupInterval: types.ZeroOr(cfg.GetCleanupInterval().AsDuration(), 30*time.Minute),
		Cache:           newFreeCache(defaultSize),
	}
}

func newFreeCache(size int) *freecache.Cache {
	return freecache.NewCache(size)
}
