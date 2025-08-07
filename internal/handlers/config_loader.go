package handlers

import (
	"context"
	"encoding/json"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/config"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/errors"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/s3"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
)

type ConfigLoader interface {
	LoadConfig(ctx context.Context) (*CheckAccessNotGrantedConfig, error)
}

type S3ConfigLoader struct {
	s3Api  s3client.S3API
	config config.ConfigManager
	logger logger.Logger
}

func NewS3ConfigLoader(s3Api s3client.S3API, configMgr config.ConfigManager, log logger.Logger) ConfigLoader {
	return &S3ConfigLoader{
		s3Api:  s3Api,
		config: configMgr,
		logger: log,
	}
}

func (loader *S3ConfigLoader) validateInputs() error {
	if loader == nil {
		return errors.ErrLoaderNil
	}
	if loader.config == nil {
		return errors.ErrConfigManagerNil
	}
	if loader.s3Api == nil {
		return errors.ErrS3APINil
	}
	return nil
}

func (loader *S3ConfigLoader) fetchConfigFromS3(ctx context.Context, bucketName, objectKey string) ([]byte, error) {
	getObjectOutput, err := loader.s3Api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return nil, errors.ErrFailedToGetConfigFromS3(err)
	}
	defer getObjectOutput.Body.Close()

	return io.ReadAll(getObjectOutput.Body)
}

func (loader *S3ConfigLoader) parseConfig(content []byte) (*CheckAccessNotGrantedConfig, error) {
	var config CheckAccessNotGrantedConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return nil, errors.ErrFailedToUnmarshalConfig(err)
	}
	return &config, nil
}

func (loader *S3ConfigLoader) LoadConfig(ctx context.Context) (*CheckAccessNotGrantedConfig, error) {
	if err := loader.validateInputs(); err != nil {
		return nil, err
	}

	bucketName := loader.config.GetConfigBucketName()
	objectKey := loader.config.GetConfigFileKey()
	loader.logger.Info("Loading config from S3: bucket=%s, key=%s", bucketName, objectKey)

	content, err := loader.fetchConfigFromS3(ctx, bucketName, objectKey)
	if err != nil {
		return nil, err
	}

	config, err := loader.parseConfig(content)
	if err != nil {
		return nil, err
	}

	if err := loader.validateConfig(config); err != nil {
		return nil, err
	}

	loader.logger.Info("Config loaded and validated successfully")
	return config, nil
}

func (loader *S3ConfigLoader) validateConfig(config *CheckAccessNotGrantedConfig) error {
	if config == nil {
		return errors.ErrConfigNil
	}
	if len(config.RestrictedActions) == 0 {
		return errors.ErrRestrictedActionsEmpty
	}

	for _, action := range config.RestrictedActions {
		if !shared.IsValidAction(action) {
			return errors.ErrInvalidRestrictedAction(action)
		}
	}

	for _, identity := range config.PrecompliantIamIdentities {
		if identity != "" && !shared.IsValidIamIdentityArn(identity) {
			return errors.ErrInvalidPrecompliantIdentity(identity)
		}
	}

	return nil
}