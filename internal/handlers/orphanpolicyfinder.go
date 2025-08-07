package handlers

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	configserviceclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	iamclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/iam"
	s3client "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/s3"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/config"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/errors"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/core"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/discovery"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/errorhandling"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/processors"
)

type OrphanPolicyFinder struct {
	s3Api        s3client.S3API
	configApi    configserviceclient.ConfigServiceApi
	logger       logger.Logger
	config       config.ConfigManager
	awsConfig    aws.Config
}

type OrphanPolicyFinderEvent struct {
	ConfigEvent events.ConfigEvent
}

type OrphanPolicyFinderConfig struct {
	TestMode bool   `json:"testMode"`
	Prefix   string `json:"prefix"`
}



func NewOrphanPolicyFinder(cfg aws.Config) (Handler[OrphanPolicyFinderEvent], error) {
	configMgr, err := config.NewConfigManager()
	if err != nil {
		return nil, err
	}

	opfHandler := &OrphanPolicyFinder{
		s3Api:     s3client.NewS3Client(awss3.NewFromConfig(cfg)),
		configApi: configserviceclient.NewConfigServiceApi(configservice.NewFromConfig(cfg)),
		logger:    logger.NewLogger(),
		config:    configMgr,
		awsConfig: cfg,
	}
	return opfHandler, nil
}

func (opf *OrphanPolicyFinder) Handle(ctx context.Context, event OrphanPolicyFinderEvent) error {
	// Load configuration
	config, err := opf.loadConfig(ctx)
	if err != nil {
		return err
	}

	// Create AWS clients for current account only
	iamClient := iamclient.NewIAMAPI(iam.NewFromConfig(opf.awsConfig))

	// Create processor and error handler
	processor := processors.NewOrphanPolicyProcessor(iamClient, opf.logger)
	errorHandler := errorhandling.NewLoggerErrorHandler(opf.logger)

	// Create worker pool
	pool := core.NewPool[OrphanPolicyRequest, OrphanPolicyResult](
		core.PoolConfig{BufferSize: core.DefaultBufferSize},
		processor,
		errorHandler,
	)

	// Discover all orphan policies in current account
	policies, err := discovery.DiscoverOrphanPolicies(ctx, iamClient)
	if err != nil {
		return errors.ErrFailedToDiscoverPolicies(err)
	}

	opf.logger.Info("Discovered %d policies to scan for orphans", len(policies))

	// Start pool and submit work
	pool.Start(ctx)
	for _, policy := range policies {
		pool.Submit(policy)
	}

	// Process results
	var wg sync.WaitGroup
	wg.Add(2)

	// Handle results
	go func() {
		defer wg.Done()
		for result := range pool.Results() {
			evaluation := opf.createConfigEvaluation(result, event.ConfigEvent.ResultToken)
			if !config.TestMode {
				opf.sendToConfigService(ctx, evaluation)
			}
		}
	}()

	// Handle errors
	go func() {
		defer wg.Done()
		for err := range pool.Errors() {
			opf.logger.Error("Orphan policy scan error: %v", err)
		}
	}()

	pool.Stop()
	wg.Wait()

	opf.logger.Info("OrphanPolicyFinder scan completed")
	return nil
}

func (opf *OrphanPolicyFinder) loadConfig(ctx context.Context) (OrphanPolicyFinderConfig, error) {
	configBucketName := opf.config.GetConfigBucketName()
	configFileObjectKey := opf.config.GetConfigFileKey()

	getObjectOutput, err := opf.s3Api.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(configBucketName),
		Key:    aws.String(configFileObjectKey),
	})
	if err != nil {
		return OrphanPolicyFinderConfig{}, errors.ErrFailedToGetConfigFromS3(err)
	}
	defer getObjectOutput.Body.Close()

	objectContent, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		return OrphanPolicyFinderConfig{}, errors.ErrFailedToReadConfigContent(err)
	}

	var config OrphanPolicyFinderConfig
	err = json.Unmarshal(objectContent, &config)
	if err != nil {
		return OrphanPolicyFinderConfig{}, errors.ErrFailedToUnmarshalConfig(err)
	}

	opf.logger.Info("OrphanPolicyFinder configuration loaded successfully")
	return config, nil
}

func (opf *OrphanPolicyFinder) createConfigEvaluation(result OrphanPolicyResult, resultToken string) configServiceTypes.Evaluation {
	return configServiceTypes.Evaluation{
		ComplianceResourceId:   aws.String(result.PolicyArn),
		ComplianceResourceType: aws.String(shared.AwsIamPolicy),
		ComplianceType:         result.ComplianceStatus,
		Annotation:             aws.String(result.Annotation),
		OrderingTimestamp:      aws.Time(result.Timestamp),
	}
}

func (opf *OrphanPolicyFinder) sendToConfigService(ctx context.Context, evaluation configServiceTypes.Evaluation) {
	_, err := opf.configApi.PutEvaluations(ctx, &configservice.PutEvaluationsInput{
		Evaluations: []configServiceTypes.Evaluation{evaluation},
	})
	if err != nil {
		opf.logger.Error("Failed to send evaluation to Config service: %v", err)
	} else {
		opf.logger.Debug("Sent evaluation to Config service for: %s", aws.ToString(evaluation.ComplianceResourceId))
	}
}
