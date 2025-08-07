package discovery

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/iam"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/core"
)

func DiscoverOrphanPolicies(ctx context.Context, iamClient iamclient.IAMAPI) ([]worker.OrphanPolicyRequest, error) {
	var requests []worker.OrphanPolicyRequest

	// Only scan customer managed policies (not AWS managed)
	paginator := iam.NewListPoliciesPaginator(iamClient, &iam.ListPoliciesInput{
		Scope:    "Local", // Only customer managed policies
		MaxItems: aws.Int32(core.MaxPageSize),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, policy := range page.Policies {
			arn := aws.ToString(policy.Arn)
			name := aws.ToString(policy.PolicyName)
			if arn == "" || name == "" {
				continue
			}
			requests = append(requests, worker.OrphanPolicyRequest{
				PolicyArn:  arn,
				PolicyName: name,
				AccountID:  extractAccountFromArn(arn),
			})
		}
	}

	return requests, nil
}