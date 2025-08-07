package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamclient "github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/awsclients/iam"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker"
	"github.com/outofoffice3/aws-samples/go-security-toolbox-v2/internal/worker/core"
)

func DiscoverIAMPrincipals(ctx context.Context, iamClient iamclient.IAMAPI) ([]worker.PolicyScanRequest, error) {
	var requests []worker.PolicyScanRequest
	rolesCount := 0
	usersCount := 0

	// Discover roles with pagination
	rolesPaginator := iam.NewListRolesPaginator(iamClient, &iam.ListRolesInput{
		MaxItems: aws.Int32(core.MaxPageSize),
	})

	for rolesPaginator.HasMorePages() {
		page, err := rolesPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM roles: %w", err)
		}

		for _, role := range page.Roles {
			arn := aws.ToString(role.Arn)
			name := aws.ToString(role.RoleName)
			if arn == "" || name == "" {
				continue
			}
			rolesCount++
			requests = append(requests, worker.PolicyScanRequest{
				PrincipalArn:  arn,
				PrincipalType: core.PrincipalTypeRole,
				PrincipalName: name,
				AccountID:     extractAccountFromArn(arn),
			})
		}
	}

	// Discover users with pagination
	usersPaginator := iam.NewListUsersPaginator(iamClient, &iam.ListUsersInput{
		MaxItems: aws.Int32(core.MaxPageSize),
	})

	for usersPaginator.HasMorePages() {
		page, err := usersPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM users: %w", err)
		}

		for _, user := range page.Users {
			arn := aws.ToString(user.Arn)
			name := aws.ToString(user.UserName)
			if arn == "" || name == "" {
				continue
			}
			usersCount++
			requests = append(requests, worker.PolicyScanRequest{
				PrincipalArn:  arn,
				PrincipalType: core.PrincipalTypeUser,
				PrincipalName: name,
				AccountID:     extractAccountFromArn(arn),
			})
		}
	}

	return requests, nil
}

func extractAccountFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}