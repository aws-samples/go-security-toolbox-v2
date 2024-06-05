package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCache(t *testing.T) {
	assertion := assert.New(t)

	resultsCache := NewCustomPolicyScanResultsCache()
	assertion.NotNil(resultsCache)
	assertion.Equal(int32(0), resultsCache.GetCacheHits())
}

func TestCache(t *testing.T) {
	assertion := assert.New(t)

	resultsCache := NewCustomPolicyScanResultsCache()
	assertion.NotNil(resultsCache)

	accountId := "123456789012"
	policyName := "test"
	testValue := "test"

	err := resultsCache.Set(CustomPolicyScanCacheKey{
		AccountID:  accountId,
		PolicyName: policyName,
	}, CustomPolicyScanCacheResult{
		Compliance: "",
		Reasons:    nil,
		Message:    testValue,
	})
	assertion.NoError(err)

	_, ok := resultsCache.Get(CustomPolicyScanCacheKey{
		AccountID:  accountId,
		PolicyName: policyName,
	})
	assertion.True(ok)
	assertion.Equal(int32(1), resultsCache.GetCacheHits())

	resultsCache.Delete(CustomPolicyScanCacheKey{
		AccountID:  accountId,
		PolicyName: policyName,
	})

	_, ok = resultsCache.Get(CustomPolicyScanCacheKey{
		AccountID:  accountId,
		PolicyName: policyName,
	})
	assertion.False(ok)
	assertion.Equal(int32(1), resultsCache.GetCacheHits())
	assertion.Equal(int32(1), resultsCache.GetCacheMisses())

	err = resultsCache.Set(CustomPolicyScanCacheKey{
		AccountID:  accountId,
		PolicyName: policyName,
	}, testValue)
	assertion.Error(err)
}
