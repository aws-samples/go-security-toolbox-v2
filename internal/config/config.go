package config

import (
	"errors"
	"os"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

type ConfigManager interface {
	GetConfigBucketName() string
	GetConfigFileKey() string
	Validate() error
}

type Config struct {
	ConfigBucketName string
	ConfigFileKey    string
}

func NewConfigManager() (ConfigManager, error) {
	config := &Config{
		ConfigBucketName: os.Getenv(shared.EnvBucketName),
		ConfigFileKey:    os.Getenv(shared.EnvConfigFileKey),
	}
	
	if err := config.Validate(); err != nil {
		return nil, err
	}
	
	return config, nil
}

func (c *Config) isValid() bool {
	return c != nil
}

func (c *Config) GetConfigBucketName() string {
	if !c.isValid() {
		return ""
	}
	return c.ConfigBucketName
}

func (c *Config) GetConfigFileKey() string {
	if !c.isValid() {
		return ""
	}
	return c.ConfigFileKey
}

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.ConfigBucketName == "" {
		return errors.New("CONFIG_FILE_BUCKET_NAME environment variable is required")
	}
	if c.ConfigFileKey == "" {
		return errors.New("CONFIG_FILE_KEY environment variable is required")
	}
	return nil
}