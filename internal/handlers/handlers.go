package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/config"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker"
)

type Config struct {
	PrecompliantIamIdentities []string `json:"precompliantIamIdentities"`
	RestrictedActions         []string `json:"restrictedActions"`
	TestMode                  bool     `json:"testMode"`
}

func RouteConfigRule(ctx context.Context, event events.ConfigEvent, cfg aws.Config) error {
	logger.Info.Printf("Processing config rule=%s", event.ConfigRuleName)

	switch event.ConfigRuleName {
	case "check-access-not-granted":
		return handlePolicyScanning(ctx, event, cfg)
	case "orphan-policy-finder":
		return handleOrphanScanning(ctx, event, cfg)
	default:
		return fmt.Errorf("unsupported config rule: %s", event.ConfigRuleName)
	}
}

func handlePolicyScanning(ctx context.Context, event events.ConfigEvent, cfg aws.Config) error {
	config, err := loadConfig(ctx, cfg)
	if err != nil {
		return err
	}

	iamClient := iam.NewFromConfig(cfg)
	accessAnalyzer := accessanalyzer.NewFromConfig(cfg)
	configClient := configservice.NewFromConfig(cfg)

	precompliantMap := make(map[string]bool)
	for _, identity := range config.PrecompliantIamIdentities {
		precompliantMap[identity] = true
	}

	principals, err := discoverPrincipals(ctx, iamClient)
	if err != nil {
		return err
	}

	logger.Info.Printf("Processing %d principals", len(principals))
	for _, p := range principals {
		result, err := worker.ScanPrincipalPolicies(ctx, p[0], p[1], p[2], iamClient, accessAnalyzer, config.RestrictedActions, precompliantMap)
		if err != nil {
			continue
		}
		if !config.TestMode {
			sendEvaluation(ctx, configClient, result.PrincipalArn, result.PrincipalType, result.ComplianceStatus, result.Annotation, result.Timestamp)
		}
	}
	return nil
}

func handleOrphanScanning(ctx context.Context, event events.ConfigEvent, cfg aws.Config) error {
	config, err := loadConfig(ctx, cfg)
	if err != nil {
		return err
	}

	iamClient := iam.NewFromConfig(cfg)
	configClient := configservice.NewFromConfig(cfg)

	policies, err := discoverPolicies(ctx, iamClient)
	if err != nil {
		return err
	}

	logger.Info.Printf("Processing %d policies", len(policies))
	for _, p := range policies {
		result, err := worker.CheckOrphanPolicy(ctx, p[0], p[1], iamClient)
		if err != nil {
			continue
		}
		if !config.TestMode {
			sendEvaluation(ctx, configClient, result.PolicyArn, "AWS::IAM::Policy", result.ComplianceStatus, result.Annotation, result.Timestamp)
		}
	}
	return nil
}

func loadConfig(ctx context.Context, cfg aws.Config) (*Config, error) {
	bucket, err := config.GetConfigBucket()
	if err != nil {
		return nil, err
	}
	key, err := config.GetConfigKey()
	if err != nil {
		return nil, err
	}

	s3Client := s3.NewFromConfig(cfg)
	obj, err := s3Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("failed to get config from S3: %w", err)
	}
	defer obj.Body.Close()

	content, err := io.ReadAll(obj.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var c Config
	if err := json.Unmarshal(content, &c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &c, nil
}

func discoverPrincipals(ctx context.Context, iamClient *iam.Client) ([][3]string, error) {
	var principals [][3]string

	rolesPaginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{})
	for rolesPaginator.HasMorePages() {
		if page, err := rolesPaginator.NextPage(ctx); err == nil {
			for _, role := range page.Roles {
				principals = append(principals, [3]string{aws.ToString(role.Arn), worker.PrincipalTypeRole, aws.ToString(role.RoleName)})
			}
		}
	}

	usersPaginator := iam.NewListUsersPaginator(iamClient, &iam.ListUsersInput{})
	for usersPaginator.HasMorePages() {
		if page, err := usersPaginator.NextPage(ctx); err == nil {
			for _, user := range page.Users {
				principals = append(principals, [3]string{aws.ToString(user.Arn), worker.PrincipalTypeUser, aws.ToString(user.UserName)})
			}
		}
	}
	return principals, nil
}

func discoverPolicies(ctx context.Context, iamClient *iam.Client) ([][2]string, error) {
	var policies [][2]string
	paginator := iam.NewListPoliciesPaginator(iamClient, &iam.ListPoliciesInput{Scope: "Local"})
	for paginator.HasMorePages() {
		if page, err := paginator.NextPage(ctx); err == nil {
			for _, pol := range page.Policies {
				policies = append(policies, [2]string{aws.ToString(pol.Arn), aws.ToString(pol.PolicyName)})
			}
		}
	}
	return policies, nil
}

func sendEvaluation(ctx context.Context, configClient *configservice.Client, resourceId, resourceType string, 
	complianceStatus configServiceTypes.ComplianceType, annotation string, timestamp time.Time) {
	
	_, err := configClient.PutEvaluations(ctx, &configservice.PutEvaluationsInput{
		Evaluations: []configServiceTypes.Evaluation{{
			ComplianceResourceId:   aws.String(resourceId),
			ComplianceResourceType: aws.String(resourceType),
			ComplianceType:         complianceStatus,
			Annotation:             aws.String(annotation),
			OrderingTimestamp:      aws.Time(timestamp),
		}},
	})
	if err != nil {
		logger.Error.Printf("Failed to send evaluation for %s: %v", resourceId, err)
	}
}