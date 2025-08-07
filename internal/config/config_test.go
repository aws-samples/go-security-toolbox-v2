package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfigManager(t *testing.T) {
	tests := []struct {
		name           string
		bucketName     string
		configFileKey  string
		expectedError  bool
		errorContains  string
	}{
		{
			name:          "Valid configuration",
			bucketName:    "test-bucket",
			configFileKey: "test-key",
			expectedError: false,
		},
		{
			name:          "Missing bucket name",
			bucketName:    "",
			configFileKey: "test-key",
			expectedError: true,
			errorContains: "CONFIG_FILE_BUCKET_NAME",
		},
		{
			name:          "Missing config file key",
			bucketName:    "test-bucket",
			configFileKey: "",
			expectedError: true,
			errorContains: "CONFIG_FILE_KEY",
		},
		{
			name:          "Missing both values",
			bucketName:    "",
			configFileKey: "",
			expectedError: true,
			errorContains: "CONFIG_FILE_BUCKET_NAME",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			os.Setenv("CONFIG_FILE_BUCKET_NAME", tt.bucketName)
			os.Setenv("CONFIG_FILE_KEY", tt.configFileKey)
			defer func() {
				os.Unsetenv("CONFIG_FILE_BUCKET_NAME")
				os.Unsetenv("CONFIG_FILE_KEY")
			}()

			config, err := NewConfigManager()

			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, config)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)
				assert.Equal(t, tt.bucketName, config.GetConfigBucketName())
				assert.Equal(t, tt.configFileKey, config.GetConfigFileKey())
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name          string
		config        *Config
		expectedError bool
		errorContains string
	}{
		{
			name: "Valid config",
			config: &Config{
				ConfigBucketName: "test-bucket",
				ConfigFileKey:    "test-key",
			},
			expectedError: false,
		},
		{
			name: "Empty bucket name",
			config: &Config{
				ConfigBucketName: "",
				ConfigFileKey:    "test-key",
			},
			expectedError: true,
			errorContains: "CONFIG_FILE_BUCKET_NAME",
		},
		{
			name: "Empty config file key",
			config: &Config{
				ConfigBucketName: "test-bucket",
				ConfigFileKey:    "",
			},
			expectedError: true,
			errorContains: "CONFIG_FILE_KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}