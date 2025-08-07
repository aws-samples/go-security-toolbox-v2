package processors

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	accessanalyzerclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/accessanalyzer"
	iamclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/iam"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/cache"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/shared"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/core"
)

type PolicyScanProcessor struct {
	iamClient                 iamclient.IAMAPI
	accessAnalyzer            accessanalyzerclient.AccessAnalyzerApi
	restrictedActions         []string
	precompliantIdentities    map[string]bool
	cache                     cache.CustomPolicyScanResultsCache
	logger                    logger.Logger
}

func NewPolicyScanProcessor(
	iamClient iamclient.IAMAPI,
	accessAnalyzer accessanalyzerclient.AccessAnalyzerApi,
	restrictedActions []string,
	precompliantIdentities []string,
	logger logger.Logger,
) *PolicyScanProcessor {
	precompliantMap := make(map[string]bool)
	for _, identity := range precompliantIdentities {
		precompliantMap[identity] = true
	}

	var cacheInstance cache.CustomPolicyScanResultsCache
	if core.CacheEnabled {
		cacheInstance = cache.NewCustomPolicyScanResultsCache()
	}

	return &PolicyScanProcessor{
		iamClient:              iamClient,
		accessAnalyzer:         accessAnalyzer,
		restrictedActions:      restrictedActions,
		precompliantIdentities: precompliantMap,
		cache:                  cacheInstance,
		logger:                 logger,
	}
}

func (p *PolicyScanProcessor) Process(ctx context.Context, request worker.PolicyScanRequest) (worker.PolicyScanResult, error) {
	p.logger.Info("Processing principal: %s", request.PrincipalArn)

	// Check if precompliant
	if p.precompliantIdentities[request.PrincipalArn] {
		return worker.PolicyScanResult{
			PrincipalArn:     request.PrincipalArn,
			PrincipalType:    request.PrincipalType,
			ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
			Annotation:       "marked as pre-compliant",
			Timestamp:        time.Now(),
		}, nil
	}

	var policyResults []worker.PolicyComplianceResult

	// Process inline policies
	inlinePolicies, err := p.getInlinePolicies(ctx, request)
	if err != nil {
		return worker.PolicyScanResult{}, err
	}
	policyResults = append(policyResults, inlinePolicies...)

	// Process managed policies
	managedPolicies, err := p.getManagedPolicies(ctx, request)
	if err != nil {
		return worker.PolicyScanResult{}, err
	}
	policyResults = append(policyResults, managedPolicies...)

	// Determine overall compliance
	overallCompliance := configServiceTypes.ComplianceTypeCompliant
	var annotations []string

	for _, result := range policyResults {
		if result.ComplianceStatus == configServiceTypes.ComplianceTypeNonCompliant {
			overallCompliance = configServiceTypes.ComplianceTypeNonCompliant
			annotations = append(annotations, result.Reasons...)
		}
	}

	annotation := strings.Join(annotations, "; ")
	if len(annotation) > 250 {
		annotation = annotation[:247] + "..."
	}

	return worker.PolicyScanResult{
		PrincipalArn:     request.PrincipalArn,
		PrincipalType:    request.PrincipalType,
		ComplianceStatus: overallCompliance,
		PolicyResults:    policyResults,
		Annotation:       annotation,
		Timestamp:        time.Now(),
	}, nil
}

func (p *PolicyScanProcessor) getInlinePolicies(ctx context.Context, request worker.PolicyScanRequest) ([]worker.PolicyComplianceResult, error) {
	var results []worker.PolicyComplianceResult

	switch request.PrincipalType {
	case core.PrincipalTypeRole:
		paginator := iam.NewListRolePoliciesPaginator(p.iamClient, &iam.ListRolePoliciesInput{
			RoleName: aws.String(request.PrincipalName),
			MaxItems: aws.Int32(core.MaxPageSize),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, policyName := range page.PolicyNames {
				policyOutput, err := p.iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
					RoleName:   aws.String(request.PrincipalName),
					PolicyName: aws.String(policyName),
				})
				if err != nil {
					continue
				}

				result, err := p.evaluatePolicy(ctx, policyName, aws.ToString(policyOutput.PolicyDocument), request.AccountID)
				if err != nil {
					continue
				}
				results = append(results, result)
			}
		}

	case core.PrincipalTypeUser:
		paginator := iam.NewListUserPoliciesPaginator(p.iamClient, &iam.ListUserPoliciesInput{
			UserName: aws.String(request.PrincipalName),
			MaxItems: aws.Int32(core.MaxPageSize),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, policyName := range page.PolicyNames {
				policyOutput, err := p.iamClient.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
					UserName:   aws.String(request.PrincipalName),
					PolicyName: aws.String(policyName),
				})
				if err != nil {
					continue
				}

				result, err := p.evaluatePolicy(ctx, policyName, aws.ToString(policyOutput.PolicyDocument), request.AccountID)
				if err != nil {
					continue
				}
				results = append(results, result)
			}
		}
	}

	return results, nil
}

func (p *PolicyScanProcessor) getManagedPolicies(ctx context.Context, request worker.PolicyScanRequest) ([]worker.PolicyComplianceResult, error) {
	var results []worker.PolicyComplianceResult

	switch request.PrincipalType {
	case core.PrincipalTypeRole:
		paginator := iam.NewListAttachedRolePoliciesPaginator(p.iamClient, &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(request.PrincipalName),
			MaxItems: aws.Int32(core.MaxPageSize),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, policy := range page.AttachedPolicies {
				result, err := p.evaluateManagedPolicy(ctx, aws.ToString(policy.PolicyName), aws.ToString(policy.PolicyArn), request.AccountID)
				if err != nil {
					continue
				}
				results = append(results, result)
			}
		}

	case core.PrincipalTypeUser:
		paginator := iam.NewListAttachedUserPoliciesPaginator(p.iamClient, &iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(request.PrincipalName),
			MaxItems: aws.Int32(core.MaxPageSize),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, policy := range page.AttachedPolicies {
				result, err := p.evaluateManagedPolicy(ctx, aws.ToString(policy.PolicyName), aws.ToString(policy.PolicyArn), request.AccountID)
				if err != nil {
					continue
				}
				results = append(results, result)
			}
		}
	}

	return results, nil
}

func (p *PolicyScanProcessor) evaluateManagedPolicy(ctx context.Context, policyName, policyArn, accountID string) (worker.PolicyComplianceResult, error) {
	// Get policy version
	policyOutput, err := p.iamClient.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return worker.PolicyComplianceResult{}, err
	}

	versionOutput, err := p.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: policyOutput.Policy.Arn,
		VersionId: policyOutput.Policy.DefaultVersionId,
	})
	if err != nil {
		return worker.PolicyComplianceResult{}, err
	}

	return p.evaluatePolicy(ctx, policyName, aws.ToString(versionOutput.PolicyVersion.Document), accountID)
}

func (p *PolicyScanProcessor) evaluatePolicy(ctx context.Context, policyName, policyDocument, accountID string) (worker.PolicyComplianceResult, error) {
	// Check cache first
	if p.cache != nil {
		cacheKey := cache.NewCacheKey(policyDocument, p.restrictedActions, accountID)
		if result, ok := p.cache.Get(cacheKey); ok {
			return worker.PolicyComplianceResult{
				PolicyName:       policyName,
				ComplianceStatus: result.Compliance,
				Reasons:          result.Reasons,
				Message:          result.Message,
			}, nil
		}
	}

	// Decode policy document
	decodedPolicy, err := url.QueryUnescape(policyDocument)
	if err != nil {
		return worker.PolicyComplianceResult{}, err
	}

	// Check with Access Analyzer
	input := &accessanalyzer.CheckAccessNotGrantedInput{
		Access: []accessAnalyzerTypes.Access{
			{
				Actions: p.restrictedActions,
			},
		},
		PolicyDocument: aws.String(decodedPolicy),
		PolicyType:     accessAnalyzerTypes.AccessCheckPolicyTypeIdentityPolicy,
	}

	output, err := p.accessAnalyzer.CheckAccessNotGranted(ctx, input)
	if err != nil {
		// Handle deny-only policies
		if strings.Contains(err.Error(), shared.DenyOnlyErrMsg) {
			result := worker.PolicyComplianceResult{
				PolicyName:       policyName,
				ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
				Message:          "deny-only policy",
			}
			p.cacheResult(decodedPolicy, accountID, result)
			return result, nil
		}
		return worker.PolicyComplianceResult{}, err
	}

	// Determine compliance
	complianceStatus := configServiceTypes.ComplianceTypeNonCompliant
	if output.Result == accessAnalyzerTypes.CheckAccessNotGrantedResultPass {
		complianceStatus = configServiceTypes.ComplianceTypeCompliant
	}

	result := worker.PolicyComplianceResult{
		PolicyName:       policyName,
		ComplianceStatus: complianceStatus,
		Reasons:          shared.ConvertReasonsToString(output.Reasons, nil),
		Message:          aws.ToString(output.Message),
	}

	p.cacheResult(decodedPolicy, accountID, result)
	return result, nil
}

func (p *PolicyScanProcessor) cacheResult(policyDocument, accountID string, result worker.PolicyComplianceResult) {
	if p.cache != nil {
		cacheKey := cache.NewCacheKey(policyDocument, p.restrictedActions, accountID)
		p.cache.Set(cacheKey, cache.CustomPolicyScanCacheResult{
			Compliance: result.ComplianceStatus,
			Reasons:    result.Reasons,
			Message:    result.Message,
		})
	}
}