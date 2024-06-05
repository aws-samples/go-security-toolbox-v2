package keyvaluestore

import (
	"sync"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

// keyValueStore interface for storing and retrieving compliance results.
type KeyValueStore interface {
	Set(key shared.Key, value interface{})
	Get(key shared.Key) (interface{}, bool)
	Delete(key shared.Key)
}

// keyValueStore implements the Cache interface using sync.Map.
type keyValueStore struct {
	store sync.Map
}

// NewCache creates a new instance of a key value store.
func NewKeyValueStore() KeyValueStore {
	return &keyValueStore{}
}

// Set stores a key-value pair in the store.
func (c *keyValueStore) Set(key shared.Key, value interface{}) {
	c.store.Store(key.ToString(), value)
}

// Get retrieves a value from the key value store based on its key.
func (c *keyValueStore) Get(key shared.Key) (interface{}, bool) {
	result, exists := c.store.Load(key.ToString())
	if !exists {
		return nil, false
	}
	return result, true
}

// delete value from key value store
func (c *keyValueStore) Delete(key shared.Key) {
	c.store.Delete(key.ToString())
}
