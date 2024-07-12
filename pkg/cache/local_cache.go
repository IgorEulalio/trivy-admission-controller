package cache

import (
	"container/list"
	"sync"
	"time"
)

// CacheItem represents a single cache item
type CacheItem struct {
	Key        string
	Value      interface{}
	Expiration int64
}

// LocalCache is an in-memory cache implementation with a maximum size and LRU eviction policy
type LocalCache struct {
	maxSize   int
	items     map[string]*list.Element
	evictList *list.List
	mu        sync.RWMutex
}

// NewLocalCache initializes a new in-memory cache with a maximum size
func NewLocalCache(maxSize int) *LocalCache {
	cache := &LocalCache{
		maxSize:   maxSize,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
	}
	go cache.startEviction()
	return cache
}

// Set adds an item to the cache
func (c *LocalCache) Set(key string, value interface{}, expiration time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.evictList.Len() >= c.maxSize {
		c.evict()
	}

	if element, found := c.items[key]; found {
		c.evictList.MoveToFront(element)
		element.Value = CacheItem{
			Key:        key,
			Value:      value,
			Expiration: time.Now().Add(expiration).UnixNano(),
		}
		return nil
	}

	item := CacheItem{
		Key:        key,
		Value:      value,
		Expiration: time.Now().Add(expiration).UnixNano(),
	}
	element := c.evictList.PushFront(item)
	c.items[key] = element
	return nil
}

// Get retrieves an item from the cache
func (c *LocalCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if element, found := c.items[key]; found {
		item := element.Value.(CacheItem)
		if time.Now().UnixNano() > item.Expiration {
			c.mu.RUnlock()
			c.mu.Lock()
			delete(c.items, key)
			c.evictList.Remove(element)
			c.mu.Unlock()
			c.mu.RLock()
			return nil, false
		}
		c.evictList.MoveToFront(element)
		return item.Value, true
	}
	return nil, false
}

// Delete removes an item from the cache
func (c *LocalCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, found := c.items[key]; found {
		delete(c.items, key)
		c.evictList.Remove(element)
	}
	return nil
}

// evict removes the least recently used item from the cache
func (c *LocalCache) evict() {
	element := c.evictList.Back()
	if element != nil {
		c.evictList.Remove(element)
		item := element.Value.(CacheItem)
		delete(c.items, item.Key)
	}
}

// startEviction starts a goroutine to periodically remove expired items
func (c *LocalCache) startEviction() {
	ticker := time.NewTicker(1 * time.Minute)
	for {
		<-ticker.C
		c.evictExpiredItems()
	}
}

// evictExpiredItems removes expired items from the cache
func (c *LocalCache) evictExpiredItems() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UnixNano()
	for key, element := range c.items {
		item := element.Value.(CacheItem)
		if now > item.Expiration {
			delete(c.items, key)
			c.evictList.Remove(element)
		}
	}
}
