package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

// RedisCache is a Redis cache implementation
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache initializes a new Redis cache
func NewRedisCache(addr string, password string, db int) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db, // TODO understand better about this
	})

	// Ping the Redis server to check the connection
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("fail to connect to Redis: %v", err)
	}

	return &RedisCache{client: client}, nil
}

// Set adds an item to the Redis cache
func (r *RedisCache) Set(key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Get retrieves an item from the Redis cache
func (r *RedisCache) Get(key string) (interface{}, bool) {
	result, err := r.client.Get(ctx, key).Result()
	if err != nil && errors.Is(err, redis.Nil) {
		return nil, false
	}
	return result, true
}

// Delete removes an item from the Redis cache
func (r *RedisCache) Delete(key string) error {
	return r.client.Del(ctx, key).Err()
}
