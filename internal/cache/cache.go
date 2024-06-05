package cache

import (
	"errors"
	"sync/atomic"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/keyvaluestore"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

type CustomPolicyScanResultsCache interface {
	Get(key CustomPolicyScanCacheKey) (interface{}, bool)
	Set(key CustomPolicyScanCacheKey, value interface{}) error
	Delete(key CustomPolicyScanCacheKey) error
	GetCacheHits() int32
	GetCacheMisses() int32
}

type _CustomPolicyScanResultsCache struct {
	cache       keyvaluestore.KeyValueStore // key value store interface for storing results
	cacheHits   atomic.Int32
	cacheMisses atomic.Int32
}

type CustomPolicyScanCacheKey struct {
	PolicyName string
	AccountID  string
}

type CustomPolicyScanCacheResult struct {
	Compliance configServiceTypes.ComplianceType
	Reasons    []string
	Message    string
}

func NewCustomPolicyScanResultsCache() CustomPolicyScanResultsCache {
	return &_CustomPolicyScanResultsCache{cache: keyvaluestore.NewKeyValueStore(),
		cacheHits:   atomic.Int32{},
		cacheMisses: atomic.Int32{}}
}

func (c *_CustomPolicyScanResultsCache) Get(key CustomPolicyScanCacheKey) (interface{}, bool) {
	result, ok := c.cache.Get(shared.Key{
		PrimaryKey: key.PolicyName,
		SortKey:    key.AccountID,
	})
	if ok {
		c.cacheHits.Add(1)
		return result, true
	}
	c.cacheMisses.Add(1)
	return nil, false
}

func (c *_CustomPolicyScanResultsCache) Set(key CustomPolicyScanCacheKey, value interface{}) error {
	valueAssert, ok := value.(CustomPolicyScanCacheResult)
	if !ok {
		return errors.New("type assertion failed. value is incorrect type")
	}
	c.cache.Set(shared.Key{
		PrimaryKey: key.PolicyName,
		SortKey:    key.AccountID,
	}, valueAssert)
	return nil
}

func (c *_CustomPolicyScanResultsCache) Delete(key CustomPolicyScanCacheKey) error {
	c.cache.Delete(shared.Key{
		PrimaryKey: key.PolicyName,
		SortKey:    key.AccountID,
	})
	return nil
}

func (c *_CustomPolicyScanResultsCache) GetCacheHits() int32 {
	return c.cacheHits.Load()
}

func (c *_CustomPolicyScanResultsCache) GetCacheMisses() int32 {
	return c.cacheMisses.Load()
}
