package keyvaluestore

import (
	"testing"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
	"github.com/stretchr/testify/assert"
)

func TestKeyValueStore(t *testing.T) {
	assertion := assert.New(t)

	// create a new key value store
	kvs := NewKeyValueStore()
	assertion.NotNil(kvs, "key value store should not be nil")

	key := shared.Key{
		PrimaryKey: "primarykey",
		SortKey:    "sortkey",
	}
	value := "testvalue"
	kvs.Set(key, value) // set value
	v, ok := kvs.Get(key)

	// get value from key value store
	assertion.True(ok, "value should be present")
	assertion.Equal(value, v, "value should match")

	// get item from key value store that does not exist
	v, ok = kvs.Get(shared.Key{
		PrimaryKey: "non-existent-pk",
		SortKey:    "non-existent-sk",
	})
	assertion.False(ok, "value should not be present")
	assertion.Empty(v, "value should be empty")
}
