package cache

import (
	"time"

	"github.com/IgorEulalio/trivy-admission-controller/pkg/config"
)

type Cache interface {
	Set(key string, value interface{}, expiration time.Duration) error
	Get(key string) (interface{}, bool)
	Delete(key string) error
}

func NewCacheFromConfig(config config.Config) (Cache, error) {
	if config.CacheConfig.RedisConfig.Address != "" {
		return NewRedisCache(
			config.CacheConfig.RedisConfig.Address,
			config.CacheConfig.RedisConfig.Password,
			config.CacheConfig.RedisConfig.DB,
		)
	} else {
		return NewLocalCache(config.CacheConfig.LocalConfig.MaxSize), nil
	}
}
