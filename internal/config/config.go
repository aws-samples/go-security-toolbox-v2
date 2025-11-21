package config

import (
	"fmt"
	"os"
)

func GetConfigBucket() (string, error) {
	bucket := os.Getenv("CONFIG_FILE_BUCKET_NAME")
	if bucket == "" {
		return "", fmt.Errorf("CONFIG_FILE_BUCKET_NAME environment variable is required")
	}
	return bucket, nil
}

func GetConfigKey() (string, error) {
	key := os.Getenv("CONFIG_FILE_KEY")
	if key == "" {
		return "", fmt.Errorf("CONFIG_FILE_KEY environment variable is required")
	}
	return key, nil
}