package cache

import (
	"sync"
	"testing"

	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/stretchr/testify/assert"
)

func TestNewCustomPolicyScanResultsCache(t *testing.T) {
	cache := NewCustomPolicyScanResultsCache()
	
	assert.NotNil(t, cache)
	assert.Equal(t, int32(0), cache.GetCacheHits())
	assert.Equal(t, int32(0), cache.GetCacheMisses())
}

func TestCustomPolicyScanCacheKey_String(t *testing.T) {
	tests := []struct {
		name     string
		key      CustomPolicyScanCacheKey
		expected string
	}{
		{
			name: "complete key",
			key: CustomPolicyScanCacheKey{
				PolicyContentHash:     "hash1",
				RestrictedActionsHash: "hash2",
				AccountID:             "123456789012",
			},
			expected: "hash1||hash2||123456789012",
		},
		{
			name: "empty values",
			key: CustomPolicyScanCacheKey{
				PolicyContentHash:     "",
				RestrictedActionsHash: "",
				AccountID:             "",
			},
			expected: "||||",
		},
		{
			name: "partial values",
			key: CustomPolicyScanCacheKey{
				PolicyContentHash:     "hash1",
				RestrictedActionsHash: "",
				AccountID:             "123456789012",
			},
			expected: "hash1||||123456789012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.key.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewCacheKey(t *testing.T) {
	tests := []struct {
		name              string
		policyDocument    string
		restrictedActions []string
		accountID         string
	}{
		{
			name:              "simple policy",
			policyDocument:    `{"Version":"2012-10-17","Statement":[]}`,
			restrictedActions: []string{"s3:GetObject", "iam:CreateUser"},
			accountID:         "123456789012",
		},
		{
			name:              "empty policy",
			policyDocument:    "",
			restrictedActions: []string{},
			accountID:         "",
		},
		{
			name:              "complex policy",
			policyDocument:    `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			restrictedActions: []string{"*"},
			accountID:         "999999999999",
		},
		{
			name:              "nil restricted actions",
			policyDocument:    "test",
			restrictedActions: nil,
			accountID:         "123456789012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := NewCacheKey(tt.policyDocument, tt.restrictedActions, tt.accountID)
			
			assert.NotEmpty(t, key.PolicyContentHash)
			assert.NotEmpty(t, key.RestrictedActionsHash)
			assert.Equal(t, tt.accountID, key.AccountID)
			assert.Len(t, key.PolicyContentHash, 64) // SHA256 hex length
			assert.Len(t, key.RestrictedActionsHash, 64) // SHA256 hex length
		})
	}
}

func TestNewCacheKey_Consistency(t *testing.T) {
	policyDoc := `{"Version":"2012-10-17"}`
	actions := []string{"s3:GetObject"}
	accountID := "123456789012"

	key1 := NewCacheKey(policyDoc, actions, accountID)
	key2 := NewCacheKey(policyDoc, actions, accountID)

	assert.Equal(t, key1, key2, "Same inputs should produce identical keys")
}

func TestNewCacheKey_Different(t *testing.T) {
	accountID := "123456789012"
	
	key1 := NewCacheKey("policy1", []string{"action1"}, accountID)
	key2 := NewCacheKey("policy2", []string{"action1"}, accountID)
	key3 := NewCacheKey("policy1", []string{"action2"}, accountID)
	key4 := NewCacheKey("policy1", []string{"action1"}, "999999999999")

	assert.NotEqual(t, key1, key2, "Different policies should produce different keys")
	assert.NotEqual(t, key1, key3, "Different actions should produce different keys")
	assert.NotEqual(t, key1, key4, "Different account IDs should produce different keys")
}

func TestCustomPolicyScanResultsCache_SetAndGet(t *testing.T) {
	tests := []struct {
		name   string
		key    CustomPolicyScanCacheKey
		value  CustomPolicyScanCacheResult
	}{
		{
			name: "compliant result",
			key: CustomPolicyScanCacheKey{
				PolicyContentHash:     "hash1",
				RestrictedActionsHash: "hash2",
				AccountID:             "123456789012",
			},
			value: CustomPolicyScanCacheResult{
				Compliance: configServiceTypes.ComplianceTypeCompliant,
				Reasons:    []string{},
				Message:    "Policy is compliant",
			},
		},
		{
			name: "non-compliant result",
			key: CustomPolicyScanCacheKey{
				PolicyContentHash:     "hash3",
				RestrictedActionsHash: "hash4",
				AccountID:             "999999999999",
			},
			value: CustomPolicyScanCacheResult{
				Compliance: configServiceTypes.ComplianceTypeNonCompliant,
				Reasons:    []string{"Contains restricted action", "Overly permissive"},
				Message:    "Policy violates security rules",
			},
		},
		{
			name: "insufficient data result",
			key: CustomPolicyScanCacheKey{
				PolicyContentHash:     "hash5",
				RestrictedActionsHash: "hash6",
				AccountID:             "111111111111",
			},
			value: CustomPolicyScanCacheResult{
				Compliance: configServiceTypes.ComplianceTypeInsufficientData,
				Reasons:    []string{"Unable to analyze"},
				Message:    "Insufficient data",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewCustomPolicyScanResultsCache()
			
			// Test Set
			err := cache.Set(tt.key, tt.value)
			assert.NoError(t, err)
			
			// Test Get - should hit
			result, found := cache.Get(tt.key)
			assert.True(t, found)
			assert.Equal(t, tt.value, result)
			assert.Equal(t, int32(1), cache.GetCacheHits())
			assert.Equal(t, int32(0), cache.GetCacheMisses())
		})
	}
}

func TestCustomPolicyScanResultsCache_GetMiss(t *testing.T) {
	cache := NewCustomPolicyScanResultsCache()
	
	key := CustomPolicyScanCacheKey{
		PolicyContentHash:     "nonexistent",
		RestrictedActionsHash: "hash",
		AccountID:             "123456789012",
	}
	
	result, found := cache.Get(key)
	assert.False(t, found)
	assert.Equal(t, CustomPolicyScanCacheResult{}, result)
	assert.Equal(t, int32(0), cache.GetCacheHits())
	assert.Equal(t, int32(1), cache.GetCacheMisses())
}

func TestCustomPolicyScanResultsCache_Delete(t *testing.T) {
	cache := NewCustomPolicyScanResultsCache()
	
	key := CustomPolicyScanCacheKey{
		PolicyContentHash:     "hash1",
		RestrictedActionsHash: "hash2",
		AccountID:             "123456789012",
	}
	
	value := CustomPolicyScanCacheResult{
		Compliance: configServiceTypes.ComplianceTypeCompliant,
		Reasons:    []string{},
		Message:    "Test",
	}
	
	// Set value
	err := cache.Set(key, value)
	assert.NoError(t, err)
	
	// Verify it exists
	_, found := cache.Get(key)
	assert.True(t, found)
	
	// Delete it
	err = cache.Delete(key)
	assert.NoError(t, err)
	
	// Verify it's gone
	_, found = cache.Get(key)
	assert.False(t, found)
}

func TestCustomPolicyScanResultsCache_NilCache(t *testing.T) {
	var cache *_CustomPolicyScanResultsCache = nil
	
	key := CustomPolicyScanCacheKey{
		PolicyContentHash:     "hash1",
		RestrictedActionsHash: "hash2",
		AccountID:             "123456789012",
	}
	
	value := CustomPolicyScanCacheResult{
		Compliance: configServiceTypes.ComplianceTypeCompliant,
		Reasons:    []string{},
		Message:    "Test",
	}
	
	// Test Get with nil cache
	result, found := cache.Get(key)
	assert.False(t, found)
	assert.Equal(t, CustomPolicyScanCacheResult{}, result)
	
	// Test Set with nil cache
	err := cache.Set(key, value)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cache is nil")
	
	// Test Delete with nil cache
	err = cache.Delete(key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cache is nil")
}

func TestCustomPolicyScanResultsCache_ConcurrentAccess(t *testing.T) {
	cache := NewCustomPolicyScanResultsCache()
	
	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100
	
	// Concurrent writes
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := CustomPolicyScanCacheKey{
					PolicyContentHash:     "hash",
					RestrictedActionsHash: "actions",
					AccountID:             "123456789012",
				}
				value := CustomPolicyScanCacheResult{
					Compliance: configServiceTypes.ComplianceTypeCompliant,
					Reasons:    []string{},
					Message:    "Concurrent test",
				}
				cache.Set(key, value)
			}
		}(i)
	}
	
	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := CustomPolicyScanCacheKey{
					PolicyContentHash:     "hash",
					RestrictedActionsHash: "actions",
					AccountID:             "123456789012",
				}
				cache.Get(key)
			}
		}(i)
	}
	
	wg.Wait()
	
	// Verify cache statistics
	hits := cache.GetCacheHits()
	misses := cache.GetCacheMisses()
	assert.True(t, hits >= 0)
	assert.True(t, misses >= 0)
	assert.Equal(t, int32(numGoroutines*numOperations), hits+misses)
}

func TestCustomPolicyScanResultsCache_MultipleKeys(t *testing.T) {
	cache := NewCustomPolicyScanResultsCache()
	
	keys := []CustomPolicyScanCacheKey{
		{PolicyContentHash: "hash1", RestrictedActionsHash: "actions1", AccountID: "111111111111"},
		{PolicyContentHash: "hash2", RestrictedActionsHash: "actions2", AccountID: "222222222222"},
		{PolicyContentHash: "hash3", RestrictedActionsHash: "actions3", AccountID: "333333333333"},
	}
	
	values := []CustomPolicyScanCacheResult{
		{Compliance: configServiceTypes.ComplianceTypeCompliant, Reasons: []string{}, Message: "Test1"},
		{Compliance: configServiceTypes.ComplianceTypeNonCompliant, Reasons: []string{"violation"}, Message: "Test2"},
		{Compliance: configServiceTypes.ComplianceTypeInsufficientData, Reasons: []string{"no data"}, Message: "Test3"},
	}
	
	// Set all values
	for i, key := range keys {
		err := cache.Set(key, values[i])
		assert.NoError(t, err)
	}
	
	// Get all values
	for i, key := range keys {
		result, found := cache.Get(key)
		assert.True(t, found)
		assert.Equal(t, values[i], result)
	}
	
	// Delete one key
	err := cache.Delete(keys[1])
	assert.NoError(t, err)
	
	// Verify deletion
	_, found := cache.Get(keys[1])
	assert.False(t, found)
	
	// Verify others still exist
	_, found = cache.Get(keys[0])
	assert.True(t, found)
	_, found = cache.Get(keys[2])
	assert.True(t, found)
}

func TestCustomPolicyScanResultsCache_OverwriteValue(t *testing.T) {
	cache := NewCustomPolicyScanResultsCache()
	
	key := CustomPolicyScanCacheKey{
		PolicyContentHash:     "hash1",
		RestrictedActionsHash: "hash2",
		AccountID:             "123456789012",
	}
	
	value1 := CustomPolicyScanCacheResult{
		Compliance: configServiceTypes.ComplianceTypeCompliant,
		Reasons:    []string{},
		Message:    "Original",
	}
	
	value2 := CustomPolicyScanCacheResult{
		Compliance: configServiceTypes.ComplianceTypeNonCompliant,
		Reasons:    []string{"violation"},
		Message:    "Updated",
	}
	
	// Set original value
	err := cache.Set(key, value1)
	assert.NoError(t, err)
	
	// Get original value
	result, found := cache.Get(key)
	assert.True(t, found)
	assert.Equal(t, value1, result)
	
	// Overwrite with new value
	err = cache.Set(key, value2)
	assert.NoError(t, err)
	
	// Get updated value
	result, found = cache.Get(key)
	assert.True(t, found)
	assert.Equal(t, value2, result)
}