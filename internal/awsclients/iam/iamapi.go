package iamclient

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// IAMAPI defines the interface for IAM operations
type IAMAPI interface {
	// ListRoles lists IAM roles
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	// ListUsers lists IAM users
	ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	// GetRolePolicy retrieves an inline policy for a role
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	// GetUserPolicy retrieves an inline policy for a user
	GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, optFns ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	// GetPolicyVersion retrieves a specific version of a managed policy
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	// GetPolicy retrieves information about a managed policy
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	// ListAttachedRolePolicies lists managed policies attached to a role
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	// ListAttachedUserPolicies lists managed policies attached to a user
	ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	// ListPolicies lists managed policies
	ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
	// ListUserPolicies lists inline policies for a user
	ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	// ListRolePolicies lists inline policies for a role
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	// ListEntitiesForPolicy lists entities attached to a policy
	ListEntitiesForPolicy(ctx context.Context, params *iam.ListEntitiesForPolicyInput, optFns ...func(*iam.Options)) (*iam.ListEntitiesForPolicyOutput, error)
}

type iamAPI struct {
	client *iam.Client
}

func NewIAMAPI(client *iam.Client) IAMAPI {
	if client == nil {
		return nil
	}
	return &iamAPI{
		client: client,
	}
}

// ListRoles lists IAM roles
func (api *iamAPI) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return api.client.ListRoles(ctx, params, optFns...)
}

// ListUsers lists IAM users
func (api *iamAPI) ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return api.client.ListUsers(ctx, params, optFns...)
}

// GetRolePolicy retrieves an inline policy for a role
func (api *iamAPI) GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	return api.client.GetRolePolicy(ctx, params, optFns...)
}

// GetUserPolicy retrieves an inline policy for a user
func (api *iamAPI) GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, optFns ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	return api.client.GetUserPolicy(ctx, params, optFns...)
}

// ListAttachedRolePolicies lists managed policies attached to a role
func (api *iamAPI) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return api.client.ListAttachedRolePolicies(ctx, params, optFns...)
}

// ListAttachedUserPolicies lists managed policies attached to a user
func (api *iamAPI) ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return api.client.ListAttachedUserPolicies(ctx, params, optFns...)
}

// ListPolicies lists managed policies
func (api *iamAPI) ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	return api.client.ListPolicies(ctx, params, optFns...)
}

// ListUserPolicies lists inline policies for a user
func (api *iamAPI) ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	return api.client.ListUserPolicies(ctx, params, optFns...)
}

// ListRolePolicies lists inline policies for a role
func (api *iamAPI) ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return api.client.ListRolePolicies(ctx, params, optFns...)
}

// GetPolicyVersion retrieves a specific version of a managed policy
func (api *iamAPI) GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	return api.client.GetPolicyVersion(ctx, params, optFns...)
}

// GetPolicy retrieves information about a managed policy
func (api *iamAPI) GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return api.client.GetPolicy(ctx, params, optFns...)
}

// ListEntitiesForPolicy lists entities attached to a policy
func (api *iamAPI) ListEntitiesForPolicy(ctx context.Context, params *iam.ListEntitiesForPolicyInput, optFns ...func(*iam.Options)) (*iam.ListEntitiesForPolicyOutput, error) {
	return api.client.ListEntitiesForPolicy(ctx, params, optFns...)
}
