package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConfigBucket(t *testing.T) {
	tests := []struct {
		name          string
		bucketName    string
		expectedError bool
	}{
		{"Valid bucket", "test-bucket", false},
		{"Empty bucket", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CONFIG_FILE_BUCKET_NAME", tt.bucketName)
			defer os.Unsetenv("CONFIG_FILE_BUCKET_NAME")

			bucket, err := GetConfigBucket()
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.bucketName, bucket)
			}
		})
	}
}

func TestGetConfigKey(t *testing.T) {
	tests := []struct {
		name          string
		configKey     string
		expectedError bool
	}{
		{"Valid key", "test-key", false},
		{"Empty key", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("CONFIG_FILE_KEY", tt.configKey)
			defer os.Unsetenv("CONFIG_FILE_KEY")

			key, err := GetConfigKey()
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.configKey, key)
			}
		})
	}
}