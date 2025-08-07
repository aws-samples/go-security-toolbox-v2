package cache

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

type CustomPolicyScanResultsCache interface {
	Get(key CustomPolicyScanCacheKey) (CustomPolicyScanCacheResult, bool)
	Set(key CustomPolicyScanCacheKey, value CustomPolicyScanCacheResult) error
	Delete(key CustomPolicyScanCacheKey) error
	GetCacheHits() int32
	GetCacheMisses() int32
}

type _CustomPolicyScanResultsCache struct {
	cache       sync.Map // direct use of sync.Map for better performance
	cacheHits   atomic.Int32
	cacheMisses atomic.Int32
}

type CustomPolicyScanCacheKey struct {
	PolicyContentHash     string
	RestrictedActionsHash string
	AccountID             string
}

func (k CustomPolicyScanCacheKey) String() string {
	return fmt.Sprintf("%s||%s||%s", k.PolicyContentHash, k.RestrictedActionsHash, k.AccountID)
}

// NewCacheKey creates a cache key from policy content and restricted actions
func NewCacheKey(policyDocument string, restrictedActions []string, accountID string) CustomPolicyScanCacheKey {
	policyHash := sha256.Sum256([]byte(policyDocument))
	actionsHash := sha256.Sum256([]byte(strings.Join(restrictedActions, ",")))
	
	return CustomPolicyScanCacheKey{
		PolicyContentHash:     fmt.Sprintf("%x", policyHash),
		RestrictedActionsHash: fmt.Sprintf("%x", actionsHash),
		AccountID:             accountID,
	}
}

type CustomPolicyScanCacheResult struct {
	Compliance configServiceTypes.ComplianceType
	Reasons    []string
	Message    string
}

func NewCustomPolicyScanResultsCache() CustomPolicyScanResultsCache {
	return &_CustomPolicyScanResultsCache{
		cache:       sync.Map{},
		cacheHits:   atomic.Int32{},
		cacheMisses: atomic.Int32{},
	}
}

func (c *_CustomPolicyScanResultsCache) Get(key CustomPolicyScanCacheKey) (CustomPolicyScanCacheResult, bool) {
	if c == nil {
		return CustomPolicyScanCacheResult{}, false
	}
	result, ok := c.cache.Load(key.String())
	if ok {
		if typedResult, typeOk := result.(CustomPolicyScanCacheResult); typeOk {
			c.cacheHits.Add(1)
			return typedResult, true
		}
		c.cache.Delete(key.String())
	}
	c.cacheMisses.Add(1)
	return CustomPolicyScanCacheResult{}, false
}

func (c *_CustomPolicyScanResultsCache) Set(key CustomPolicyScanCacheKey, value CustomPolicyScanCacheResult) error {
	if c == nil {
		return errors.New("cache is nil")
	}
	c.cache.Store(key.String(), value)
	return nil
}

func (c *_CustomPolicyScanResultsCache) Delete(key CustomPolicyScanCacheKey) error {
	if c == nil {
		return errors.New("cache is nil")
	}
	c.cache.Delete(key.String())
	return nil
}

func (c *_CustomPolicyScanResultsCache) GetCacheHits() int32 {
	return c.cacheHits.Load()
}

func (c *_CustomPolicyScanResultsCache) GetCacheMisses() int32 {
	return c.cacheMisses.Load()
}
