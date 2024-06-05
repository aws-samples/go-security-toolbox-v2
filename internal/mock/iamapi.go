package mock

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type MockIamApi struct {
}

var (
	TestPolicyCreatedDate = aws.Time(time.Date(2024, time.January, 1, 1, 1, 1, 1, time.Now().Location()))
	TestPolicyUpdatedDate = aws.Time(time.Date(2024, time.January, 1, 1, 1, 1, 1, time.Now().Location()))

	TestRoleArn                 = "test-role-arn"
	TestRoleName                = "test-role-name"
	TestErrorRoleArn            = "test-error-role-arn"
	TestErrorRoleName           = "test-error-role-name"
	TestRoleWithErrorPolicyArn  = "test-role-with-error-policy-arn"
	TestRoleWithErrorPolicyName = "test-role-with-error-policy-name"

	TestUserArn                 = "test-user-arn"
	TestUserName                = "test-user-name"
	TestErrorUserArn            = "test-error-user-arn"
	TestErrorUserName           = "test-error-user-name"
	TestUserWithErrorPolicyArn  = "test-user-with-error-policy-arn"
	TestUserWithErrorPolicyName = "test-user-with-error-policy-name"

	TestCompliantPolicyName = "test-compliant-policy-name"
	TestCompliantPolicyArn  = "test-compliant-policy-arn"

	TestErrorPolicyName = "test-error-policy-name"
	TestErrorPolicyArn  = "test-error-policy-arn"

	TestNonCompliantPolicyName = "test-non-compliant-policy-name"
	TestNonCompliantPolicyArn  = "test-non-compliant-policy-arn"
)

// list roles
func (m *MockIamApi) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{
		Roles: []iamTypes.Role{
			{
				Arn:      aws.String(TestRoleArn),
				RoleName: aws.String(TestRoleName),
			},
			{
				Arn:      aws.String(TestRoleWithErrorPolicyArn),
				RoleName: aws.String(TestRoleWithErrorPolicyName),
			},
			{
				Arn:      aws.String(TestErrorRoleArn),
				RoleName: aws.String(TestErrorRoleName),
			},
		},
	}, nil
}

// list users
func (m *MockIamApi) ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{
		Users: []iamTypes.User{
			{
				UserName: aws.String(TestUserName),
				Arn:      aws.String(TestUserArn),
			},
			{
				UserName: aws.String(TestUserWithErrorPolicyName),
				Arn:      aws.String(TestUserWithErrorPolicyArn),
			},
			{
				UserName: aws.String(TestErrorUserName),
				Arn:      aws.String(TestErrorUserArn),
			},
		},
	}, nil
}

// get role policy
func (m *MockIamApi) GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	if *params.PolicyName == TestCompliantPolicyName {
		return &iam.GetRolePolicyOutput{
			PolicyDocument: aws.String(TestCompliantPolicyDocument),
			PolicyName:     aws.String(TestCompliantPolicyName),
			RoleName:       aws.String(TestRoleName),
		}, nil
	} else if *params.PolicyName == TestNonCompliantPolicyName {
		return &iam.GetRolePolicyOutput{
			PolicyDocument: aws.String(TestNonCompliantPolicyDocument),
			PolicyName:     aws.String(TestNonCompliantPolicyName),
			RoleName:       aws.String(TestRoleName),
		}, nil
	} else if *params.PolicyName == TestRoleWithErrorPolicyName {
		return &iam.GetRolePolicyOutput{
			PolicyDocument: aws.String(TestErrorPolicyDocument),
			PolicyName:     aws.String(TestErrorPolicyName),
			RoleName:       aws.String(TestRoleWithErrorPolicyName),
		}, nil
	} else {
		return nil, errors.New("get role policy error")
	}
}

// get user policy
func (m *MockIamApi) GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, optFns ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	if *params.PolicyName == TestCompliantPolicyName {
		return &iam.GetUserPolicyOutput{
			PolicyDocument: aws.String(TestCompliantPolicyDocument),
			PolicyName:     aws.String(TestCompliantPolicyName),
			UserName:       aws.String(TestUserName),
		}, nil
	} else if *params.PolicyName == TestNonCompliantPolicyName {
		return &iam.GetUserPolicyOutput{
			PolicyDocument: aws.String(TestNonCompliantPolicyDocument),
			PolicyName:     aws.String(TestNonCompliantPolicyName),
			UserName:       aws.String(TestUserName),
		}, nil
	} else if *params.PolicyName == TestUserWithErrorPolicyName {
		return &iam.GetUserPolicyOutput{
			PolicyDocument: aws.String(TestErrorPolicyDocument),
			PolicyName:     aws.String(TestErrorPolicyName),
			UserName:       aws.String(TestUserWithErrorPolicyName),
		}, nil
	} else {
		return nil, errors.New("get user policy error")
	}
}

// list attached role policies
func (m *MockIamApi) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	if *params.RoleName == TestRoleWithErrorPolicyName {
		return &iam.ListAttachedRolePoliciesOutput{
			AttachedPolicies: []iamTypes.AttachedPolicy{
				{
					PolicyArn:  aws.String(TestErrorPolicyArn),
					PolicyName: aws.String(TestErrorPolicyName),
				},
			},
		}, nil
	} else if *params.RoleName == TestRoleName {
		return &iam.ListAttachedRolePoliciesOutput{
			AttachedPolicies: []iamTypes.AttachedPolicy{
				{
					PolicyArn:  aws.String(TestCompliantPolicyArn),
					PolicyName: aws.String(TestCompliantPolicyName),
				},
				{
					PolicyArn:  aws.String(TestNonCompliantPolicyArn),
					PolicyName: aws.String(TestNonCompliantPolicyName),
				},
			},
		}, nil
	} else {
		return nil, errors.New("list attached role policies error")
	}
}

// list attached user policies
func (m *MockIamApi) ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	if *params.UserName == TestUserWithErrorPolicyName {
		return &iam.ListAttachedUserPoliciesOutput{
			AttachedPolicies: []iamTypes.AttachedPolicy{
				{
					PolicyArn:  aws.String(TestErrorPolicyArn),
					PolicyName: aws.String(TestErrorPolicyName),
				},
			},
		}, nil
	} else if *params.UserName == TestUserName {
		return &iam.ListAttachedUserPoliciesOutput{
			AttachedPolicies: []iamTypes.AttachedPolicy{
				{
					PolicyArn:  aws.String(TestCompliantPolicyArn),
					PolicyName: aws.String(TestCompliantPolicyName),
				},
				{
					PolicyArn:  aws.String(TestNonCompliantPolicyArn),
					PolicyName: aws.String(TestNonCompliantPolicyName),
				},
			},
		}, nil
	} else {
		return nil, errors.New("list attached user policies error")
	}
}

// list policies
func (m *MockIamApi) ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	return &iam.ListPoliciesOutput{
		Policies: []iamTypes.Policy{
			{
				PolicyName:      aws.String(TestCompliantPolicyName),
				Arn:             aws.String(TestCompliantPolicyArn),
				AttachmentCount: aws.Int32(0),
				CreateDate:      TestPolicyCreatedDate,
				UpdateDate:      TestPolicyUpdatedDate,
			},
			{
				PolicyName:      aws.String(TestNonCompliantPolicyName),
				Arn:             aws.String(TestNonCompliantPolicyArn),
				AttachmentCount: aws.Int32(1),
				CreateDate:      TestPolicyCreatedDate,
				UpdateDate:      TestPolicyUpdatedDate,
			},
		},
	}, nil
}

// list role policies
func (m *MockIamApi) ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	if *params.RoleName == TestRoleName {
		return &iam.ListRolePoliciesOutput{
			PolicyNames: []string{TestCompliantPolicyName, TestNonCompliantPolicyName},
		}, nil
	} else if *params.RoleName == TestRoleWithErrorPolicyName {
		return &iam.ListRolePoliciesOutput{
			PolicyNames: []string{TestErrorPolicyName},
		}, nil
	} else {
		return nil, errors.New("list role policies error")
	}
}

// list user policies
func (m *MockIamApi) ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	if *params.UserName == TestUserName {
		return &iam.ListUserPoliciesOutput{
			PolicyNames: []string{TestCompliantPolicyName, TestNonCompliantPolicyName},
		}, nil
	} else if *params.UserName == TestUserWithErrorPolicyName {
		return &iam.ListUserPoliciesOutput{
			PolicyNames: []string{TestErrorPolicyName},
		}, nil
	} else {
		return nil, errors.New("list user policies error")
	}
}

// get policy version
func (m *MockIamApi) GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return &iam.GetPolicyVersionOutput{}, nil
}

// get policy
func (m *MockIamApi) GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{}, nil
}
