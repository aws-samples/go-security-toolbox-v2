package worker

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessAnalyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func ScanPrincipalPolicies(ctx context.Context, principalArn, principalType, principalName string, 
	iamClient *iam.Client, accessAnalyzer *accessanalyzer.Client, restrictedActions []string, 
	precompliantIdentities map[string]bool) (PolicyScanResult, error) {
	
	if precompliantIdentities[principalArn] {
		return PolicyScanResult{
			PrincipalArn:     principalArn,
			PrincipalType:    principalType,
			ComplianceStatus: configServiceTypes.ComplianceTypeCompliant,
			Annotation:       "marked as pre-compliant",
			Timestamp:        time.Now(),
		}, nil
	}
	
	var violations []string
	checkPolicies(ctx, principalType, principalName, iamClient, accessAnalyzer, restrictedActions, &violations)
	
	complianceStatus := configServiceTypes.ComplianceTypeCompliant
	annotation := "no violations found"
	if len(violations) > 0 {
		complianceStatus = configServiceTypes.ComplianceTypeNonCompliant
		annotation = strings.Join(violations, "; ")
		if len(annotation) > 250 {
			annotation = annotation[:247] + "..."
		}
	}
	
	return PolicyScanResult{
		PrincipalArn:     principalArn,
		PrincipalType:    principalType,
		ComplianceStatus: complianceStatus,
		Annotation:       annotation,
		Timestamp:        time.Now(),
	}, nil
}

func checkPolicies(ctx context.Context, principalType, principalName string, iamClient *iam.Client, 
	accessAnalyzer *accessanalyzer.Client, restrictedActions []string, violations *[]string) {
	
	// Check inline policies
	if principalType == PrincipalTypeRole {
		paginator := iam.NewListRolePoliciesPaginator(iamClient, &iam.ListRolePoliciesInput{RoleName: aws.String(principalName)})
		for paginator.HasMorePages() {
			if page, err := paginator.NextPage(ctx); err == nil {
				for _, policyName := range page.PolicyNames {
					if policyOutput, err := iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
						RoleName: aws.String(principalName), PolicyName: aws.String(policyName)}); err == nil {
						checkPolicy(ctx, policyName, aws.ToString(policyOutput.PolicyDocument), accessAnalyzer, restrictedActions, violations)
					}
				}
			}
		}
		// Check managed policies
		managedPaginator := iam.NewListAttachedRolePoliciesPaginator(iamClient, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(principalName)})
		for managedPaginator.HasMorePages() {
			if page, err := managedPaginator.NextPage(ctx); err == nil {
				for _, policy := range page.AttachedPolicies {
					checkManagedPolicy(ctx, aws.ToString(policy.PolicyName), aws.ToString(policy.PolicyArn), iamClient, accessAnalyzer, restrictedActions, violations)
				}
			}
		}
	} else {
		paginator := iam.NewListUserPoliciesPaginator(iamClient, &iam.ListUserPoliciesInput{UserName: aws.String(principalName)})
		for paginator.HasMorePages() {
			if page, err := paginator.NextPage(ctx); err == nil {
				for _, policyName := range page.PolicyNames {
					if policyOutput, err := iamClient.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
						UserName: aws.String(principalName), PolicyName: aws.String(policyName)}); err == nil {
						checkPolicy(ctx, policyName, aws.ToString(policyOutput.PolicyDocument), accessAnalyzer, restrictedActions, violations)
					}
				}
			}
		}
		// Check managed policies
		managedPaginator := iam.NewListAttachedUserPoliciesPaginator(iamClient, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(principalName)})
		for managedPaginator.HasMorePages() {
			if page, err := managedPaginator.NextPage(ctx); err == nil {
				for _, policy := range page.AttachedPolicies {
					checkManagedPolicy(ctx, aws.ToString(policy.PolicyName), aws.ToString(policy.PolicyArn), iamClient, accessAnalyzer, restrictedActions, violations)
				}
			}
		}
	}
}

func checkManagedPolicy(ctx context.Context, policyName, policyArn string, iamClient *iam.Client, 
	accessAnalyzer *accessanalyzer.Client, restrictedActions []string, violations *[]string) {
	
	if policyOutput, err := iamClient.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyArn)}); err == nil {
		if versionOutput, err := iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: policyOutput.Policy.Arn, VersionId: policyOutput.Policy.DefaultVersionId}); err == nil {
			checkPolicy(ctx, policyName, aws.ToString(versionOutput.PolicyVersion.Document), accessAnalyzer, restrictedActions, violations)
		}
	}
}

func checkPolicy(ctx context.Context, policyName, policyDocument string, accessAnalyzer *accessanalyzer.Client, 
	restrictedActions []string, violations *[]string) {
	
	decodedPolicy, err := url.QueryUnescape(policyDocument)
	if err != nil {
		return
	}
	
	output, err := accessAnalyzer.CheckAccessNotGranted(ctx, &accessanalyzer.CheckAccessNotGrantedInput{
		Access: []accessAnalyzerTypes.Access{{Actions: restrictedActions}},
		PolicyDocument: aws.String(decodedPolicy),
		PolicyType: accessAnalyzerTypes.AccessCheckPolicyTypeIdentityPolicy,
	})
	
	if err == nil && output.Result == accessAnalyzerTypes.CheckAccessNotGrantedResultFail {
		reasons := convertReasonsToString(output.Reasons)
		*violations = append(*violations, fmt.Sprintf("Policy %s: %s", policyName, strings.Join(reasons, ", ")))
	}
}

func CheckOrphanPolicy(ctx context.Context, policyArn, policyName string, iamClient *iam.Client) (OrphanPolicyResult, error) {
	entitiesOutput, err := iamClient.ListEntitiesForPolicy(ctx, &iam.ListEntitiesForPolicyInput{PolicyArn: aws.String(policyArn)})
	if err != nil {
		return OrphanPolicyResult{}, err
	}
	
	totalAttachments := len(entitiesOutput.PolicyUsers) + len(entitiesOutput.PolicyRoles) + len(entitiesOutput.PolicyGroups)
	complianceStatus := configServiceTypes.ComplianceTypeCompliant
	annotation := "Policy is attached to IAM principals"
	
	if totalAttachments == 0 {
		complianceStatus = configServiceTypes.ComplianceTypeNonCompliant
		annotation = "Policy is not attached to any IAM principals"
	}
	
	return OrphanPolicyResult{
		PolicyArn: policyArn, PolicyName: policyName,
		ComplianceStatus: complianceStatus, Annotation: annotation,
		Timestamp: time.Now(),
	}, nil
}