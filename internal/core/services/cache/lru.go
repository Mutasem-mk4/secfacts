package cache

import (
	"container/list"
	"sync"
)

// LRUCache is a simple thread-safe LRU cache for deduplication.
type LRUCache struct {
	capacity int
	items    map[string]*list.Element
	evictList *list.List
	mu       sync.RWMutex
}

type entry struct {
	key string
}

// NewLRUCache creates a new LRUCache with the specified capacity.
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity:  capacity,
		items:     make(map[string]*list.Element),
		evictList: list.New(),
	}
}

// Add adds a key to the cache. Returns true if the key already existed.
func (c *LRUCache) Add(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		return true
	}

	ent := c.evictList.PushFront(&entry{key})
	c.items[key] = ent

	if c.evictList.Len() > c.capacity {
		c.removeOldest()
	}

	return false
}

// Contains checks if a key is in the cache without moving it.
func (c *LRUCache) Contains(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.items[key]
	return ok
}

func (c *LRUCache) removeOldest() {
	ent := c.evictList.Back()
	if ent != nil {
		c.evictList.Remove(ent)
		kv := ent.Value.(*entry)
		delete(c.items, kv.key)
	}
}
