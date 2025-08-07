package processors

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	configServiceTypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	iamclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/iam"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/logger"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/core"
)

type OrphanPolicyProcessor struct {
	iamClient iamclient.IAMAPI
	logger    logger.Logger
}

func NewOrphanPolicyProcessor(iamClient iamclient.IAMAPI, logger logger.Logger) *OrphanPolicyProcessor {
	return &OrphanPolicyProcessor{
		iamClient: iamClient,
		logger:    logger,
	}
}

func (p *OrphanPolicyProcessor) Process(ctx context.Context, request worker.OrphanPolicyRequest) (worker.OrphanPolicyResult, error) {
	p.logger.Debug("Starting orphan policy check for policy_arn=%s policy_name=%s", request.PolicyArn, request.PolicyName)

	// Check if policy is attached to any entities
	entitiesOutput, err := p.iamClient.ListEntitiesForPolicy(ctx, &iam.ListEntitiesForPolicyInput{
		PolicyArn: aws.String(request.PolicyArn),
		MaxItems:  aws.Int32(core.MaxPageSize),
	})
	if err != nil {
		p.logger.Error("Failed to list entities for policy policy_arn=%s error=%v", request.PolicyArn, err)
		return worker.OrphanPolicyResult{}, err
	}

	// Determine if policy is orphaned
	usersCount := len(entitiesOutput.PolicyUsers)
	rolesCount := len(entitiesOutput.PolicyRoles)
	groupsCount := len(entitiesOutput.PolicyGroups)
	totalAttachments := usersCount + rolesCount + groupsCount
	
	p.logger.Debug("Policy attachment analysis policy_arn=%s users=%d roles=%d groups=%d total_attachments=%d", 
		request.PolicyArn, usersCount, rolesCount, groupsCount, totalAttachments)

	isOrphaned := totalAttachments == 0

	var complianceStatus configServiceTypes.ComplianceType
	var annotation string

	if isOrphaned {
		complianceStatus = configServiceTypes.ComplianceTypeNonCompliant
		annotation = "Policy is not attached to any IAM principals"
		p.logger.Warn("Orphaned policy detected policy_arn=%s policy_name=%s", request.PolicyArn, request.PolicyName)
	} else {
		complianceStatus = configServiceTypes.ComplianceTypeCompliant
		annotation = "Policy is attached to IAM principals"
		p.logger.Info("Policy compliance verified policy_arn=%s policy_name=%s attachments=%d", 
			request.PolicyArn, request.PolicyName, totalAttachments)
	}

	return worker.OrphanPolicyResult{
		PolicyArn:        request.PolicyArn,
		PolicyName:       request.PolicyName,
		ComplianceStatus: complianceStatus,
		Annotation:       annotation,
		Timestamp:        time.Now(),
	}, nil
}