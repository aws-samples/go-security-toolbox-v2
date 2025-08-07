package handlers

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	configserviceclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/configservice"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	accessanalyzerclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/accessanalyzer"
	iamclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/iam"
	s3client "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/s3"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/config"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/errors"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/core"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/discovery"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/errorhandling"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/processors"
)

type Handler[T any] interface {
	Handle(ctx context.Context, params T) error
}

// Use worker types directly
type PolicyScanRequest = worker.PolicyScanRequest
type PolicyScanResult = worker.PolicyScanResult
type OrphanPolicyRequest = worker.OrphanPolicyRequest
type OrphanPolicyResult = worker.OrphanPolicyResult

type CheckAccessNotGrantedHandler struct {
	s3Api        s3client.S3API
	configApi    configserviceclient.ConfigServiceApi
	logger       logger.Logger
	config       config.ConfigManager
	awsConfig    aws.Config
}

type CheckAccessNotGrantedEvent struct {
	ConfigEvent events.ConfigEvent
}

type CheckAccessNotGrantedConfig struct {
	PrecompliantIamIdentities []string `json:"precompliantIamIdentities"`
	RestrictedActions         []string `json:"restrictedActions"`
	TestMode                  bool     `json:"testMode"`
	Prefix                    string   `json:"prefix"`
}

func NewCheckAccessNotGrantedHandler(cfg aws.Config, log logger.Logger, configMgr config.ConfigManager) (Handler[CheckAccessNotGrantedEvent], error) {
	if log == nil {
		log = logger.NewLogger()
	}
	if configMgr == nil {
		return nil, errors.ErrConfigManagerRequired
	}

	cangHandler := &CheckAccessNotGrantedHandler{
		s3Api:     s3client.NewS3Client(awss3.NewFromConfig(cfg)),
		configApi: configserviceclient.NewConfigServiceApi(configservice.NewFromConfig(cfg)),
		logger:    log,
		config:    configMgr,
		awsConfig: cfg,
	}

	return cangHandler, nil
}

func (cang *CheckAccessNotGrantedHandler) Handle(ctx context.Context, event CheckAccessNotGrantedEvent) error {
	cang.logger.Info("Starting CheckAccessNotGranted scan result_token=%s", event.ConfigEvent.ResultToken)

	// Load configuration
	config, err := cang.loadConfig(ctx)
	if err != nil {
		cang.logger.Error("Failed to load configuration error=%v", err)
		return err
	}

	cang.logger.Debug("Configuration loaded restricted_actions=%d precompliant_identities=%d test_mode=%t", 
		len(config.RestrictedActions), len(config.PrecompliantIamIdentities), config.TestMode)

	// Create AWS clients for current account/region only
	iamClient := iamclient.NewIAMAPI(iam.NewFromConfig(cang.awsConfig))
	accessAnalyzer := accessanalyzerclient.NewAccessAnalyzerApi(accessanalyzer.NewFromConfig(cang.awsConfig))

	// Create processor and error handler
	processor := processors.NewPolicyScanProcessor(
		iamClient,
		accessAnalyzer,
		config.RestrictedActions,
		config.PrecompliantIamIdentities,
		cang.logger,
	)

	errorHandler := errorhandling.NewLoggerErrorHandler(cang.logger)

	// Create worker pool
	pool := core.NewPool[PolicyScanRequest, PolicyScanResult](
		core.PoolConfig{BufferSize: core.DefaultBufferSize},
		processor,
		errorHandler,
	)

	// Discover all IAM principals in current account
	cang.logger.Debug("Starting IAM principal discovery")
	principals, err := discovery.DiscoverIAMPrincipals(ctx, iamClient)
	if err != nil {
		cang.logger.Error("Failed to discover IAM principals error=%v", err)
		return errors.ErrFailedToDiscoverPrincipals(err)
	}

	cang.logger.Info("IAM principal discovery completed principals_count=%d", len(principals))

	// Start pool and submit work
	cang.logger.Debug("Starting worker pool with buffer_size=%d", core.DefaultBufferSize)
	pool.Start(ctx)
	submittedCount := 0
	for _, principal := range principals {
		if pool.Submit(principal) {
			submittedCount++
		} else {
			cang.logger.Warn("Failed to submit principal to worker pool principal_arn=%s", principal.PrincipalArn)
		}
	}
	cang.logger.Info("Work submission completed submitted=%d total=%d", submittedCount, len(principals))

	// Process results
	var wg sync.WaitGroup
	wg.Add(2)

	// Handle results
	resultCount := 0
	go func() {
		defer wg.Done()
		for result := range pool.Results() {
			resultCount++
			cang.logger.Debug("Processing scan result principal_arn=%s compliance=%s result_count=%d", 
				result.PrincipalArn, result.ComplianceStatus, resultCount)
			
			evaluation := cang.createConfigEvaluation(result, event.ConfigEvent.ResultToken)
			if !config.TestMode {
				cang.sendToConfigService(ctx, evaluation)
			} else {
				cang.logger.Debug("Test mode enabled - skipping Config service submission")
			}
		}
		cang.logger.Info("Result processing completed total_results=%d", resultCount)
	}()

	// Handle errors
	errorCount := 0
	go func() {
		defer wg.Done()
		for err := range pool.Errors() {
			errorCount++
			cang.logger.Error("Policy scan processing error error_count=%d error=%v", errorCount, err)
		}
		if errorCount > 0 {
			cang.logger.Warn("Scan completed with errors total_errors=%d", errorCount)
		}
	}()

	pool.Stop()
	wg.Wait()

	cang.logger.Info("CheckAccessNotGranted scan completed successfully principals_processed=%d results=%d errors=%d", 
		len(principals), resultCount, errorCount)
	return nil
}

func (cang *CheckAccessNotGrantedHandler) loadConfig(ctx context.Context) (CheckAccessNotGrantedConfig, error) {
	configBucketName := cang.config.GetConfigBucketName()
	configFileObjectKey := cang.config.GetConfigFileKey()
	cang.logger.Debug("Loading configuration from S3 bucket=%s key=%s", configBucketName, configFileObjectKey)

	getObjectOutput, err := cang.s3Api.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(configBucketName),
		Key:    aws.String(configFileObjectKey),
	})
	if err != nil {
		cang.logger.Error("Failed to retrieve config from S3 bucket=%s key=%s error=%v", configBucketName, configFileObjectKey, err)
		return CheckAccessNotGrantedConfig{}, errors.ErrFailedToGetConfigFromS3(err)
	}
	defer getObjectOutput.Body.Close()

	objectContent, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		cang.logger.Error("Failed to read config content error=%v", err)
		return CheckAccessNotGrantedConfig{}, errors.ErrFailedToReadConfigContent(err)
	}

	var config CheckAccessNotGrantedConfig
	err = json.Unmarshal(objectContent, &config)
	if err != nil {
		cang.logger.Error("Failed to unmarshal config JSON error=%v", err)
		return CheckAccessNotGrantedConfig{}, errors.ErrFailedToUnmarshalConfig(err)
	}

	cang.logger.Debug("Config unmarshaled successfully - starting validation")

	// Validate restricted actions
	if len(config.RestrictedActions) == 0 {
		cang.logger.Error("Configuration validation failed - no restricted actions specified")
		return CheckAccessNotGrantedConfig{}, errors.ErrRestrictedActionsEmpty
	}

	for i, restrictedAction := range config.RestrictedActions {
		if !shared.IsValidAction(restrictedAction) {
			cang.logger.Error("Invalid restricted action at index=%d action=%s", i, restrictedAction)
			return CheckAccessNotGrantedConfig{}, errors.ErrInvalidRestrictedAction(restrictedAction)
		}
	}

	// Validate precompliant identities
	for i, precompliantIamIdentity := range config.PrecompliantIamIdentities {
		if precompliantIamIdentity != "" && !shared.IsValidIamIdentityArn(precompliantIamIdentity) {
			cang.logger.Error("Invalid precompliant IAM identity at index=%d identity=%s", i, precompliantIamIdentity)
			return CheckAccessNotGrantedConfig{}, errors.ErrInvalidPrecompliantIdentity(precompliantIamIdentity)
		}
	}

	cang.logger.Info("Configuration validation completed successfully restricted_actions=%d precompliant_identities=%d", 
		len(config.RestrictedActions), len(config.PrecompliantIamIdentities))
	return config, nil
}

func (cang *CheckAccessNotGrantedHandler) createConfigEvaluation(result PolicyScanResult, resultToken string) configServiceTypes.Evaluation {
	return configServiceTypes.Evaluation{
		ComplianceResourceId:   aws.String(result.PrincipalArn),
		ComplianceResourceType: aws.String(result.PrincipalType),
		ComplianceType:         result.ComplianceStatus,
		Annotation:             aws.String(result.Annotation),
		OrderingTimestamp:      aws.Time(result.Timestamp),
	}
}

func (cang *CheckAccessNotGrantedHandler) sendToConfigService(ctx context.Context, evaluation configServiceTypes.Evaluation) {
	resourceId := aws.ToString(evaluation.ComplianceResourceId)
	resourceType := aws.ToString(evaluation.ComplianceResourceType)
	
	cang.logger.Debug("Sending evaluation to Config service resource_id=%s resource_type=%s compliance=%s", 
		resourceId, resourceType, evaluation.ComplianceType)
	
	_, err := cang.configApi.PutEvaluations(ctx, &configservice.PutEvaluationsInput{
		Evaluations: []configServiceTypes.Evaluation{evaluation},
	})
	if err != nil {
		cang.logger.Error("Failed to send evaluation to Config service resource_id=%s error=%v", resourceId, err)
	} else {
		cang.logger.Debug("Successfully sent evaluation to Config service resource_id=%s", resourceId)
	}
}