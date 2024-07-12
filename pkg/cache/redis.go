package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(addr string, password string, db int) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db, // TODO understand better about this
	})

	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("fail to connect to Redis: %v", err)
	}

	return &RedisCache{client: client}, nil
}

func (r *RedisCache) Set(key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

func (r *RedisCache) Get(key string) (interface{}, bool) {
	result, err := r.client.Get(ctx, key).Result()
	if err != nil && errors.Is(err, redis.Nil) {
		return nil, false
	}
	return result, true
}

func (r *RedisCache) Delete(key string) error {
	return r.client.Del(ctx, key).Err()
}
